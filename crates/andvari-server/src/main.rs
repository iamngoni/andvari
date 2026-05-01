use actix_web::middleware::from_fn;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use tracing::{info, warn};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{EnvFilter, fmt};

mod api;
mod audit;
mod auth;
mod db;
mod kms;
mod log_redact;
mod metrics;
mod middleware;
mod oidc;
mod state;
mod sys;
mod ui;

async fn not_found() -> impl Responder {
    HttpResponse::NotFound().json(serde_json::json!({ "error": "not found" }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let bind = std::env::var("ANDVARI_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());

    let pool = match db::connect().await {
        Ok(pool) => match db::migrate(&pool).await {
            Ok(()) => Some(pool),
            Err(e) => {
                warn!(error = %e, "migrations failed; continuing without database");
                None
            }
        },
        Err(e) => {
            warn!(error = %e, "database connection failed; continuing without database");
            None
        }
    };

    let app_state = match pool {
        Some(pool) => state::AppState::new().with_db(pool),
        None => state::AppState::new(),
    };

    // Optional OIDC bootstrap.
    let app_state = if let Some(oidc_cfg) = oidc::OidcConfig::from_env() {
        match oidc::Provider::discover(&oidc_cfg).await {
            Ok(p) => {
                info!(issuer = %oidc_cfg.issuer, "oidc discovery complete");
                app_state.with_oidc(std::sync::Arc::new(p))
            }
            Err(e) => {
                warn!(error = %e, "oidc discovery failed; oidc endpoints will return 503");
                app_state
            }
        }
    } else {
        app_state
    };

    match state::unseal_from_env(&app_state.vault).await {
        Ok(true) => info!("env-var unseal succeeded; vault is unsealed"),
        Ok(false) => info!("ANDVARI_ROOT_KEY not set; vault remains sealed"),
        Err(e) => warn!(error = %e, "env-var unseal failed; vault remains sealed"),
    }

    if app_state.vault.read().await.is_sealed() {
        if let Some(kms_cfg) = state::KmsUnsealConfig::from_env() {
            match state::unseal_from_kms(&app_state.vault, &kms_cfg).await {
                Ok(_) => info!(provider = %kms_cfg.provider, "kms unseal succeeded"),
                Err(e) => warn!(error = %e, "kms unseal failed; vault remains sealed"),
            }
        }
    }

    let threshold = match state::shamir_threshold_from_env() {
        Ok(t) => t,
        Err(e) => {
            warn!(error = %e, "ANDVARI_SHAMIR_THRESHOLD malformed; ignoring");
            None
        }
    };
    if let Err(e) = state::init_shamir_progress(&app_state, threshold).await {
        warn!(error = %e, "shamir progress init failed; /v1/sys/unseal will reject");
    } else if let Some(t) = threshold {
        if app_state.unseal.read().await.is_some() {
            info!(threshold = t, "shamir unseal mode active");
        }
    }

    info!(%bind, "andvari-server starting");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(TracingLogger::default())
            .wrap(from_fn(middleware::require_unsealed))
            .wrap(from_fn(auth::resolve_identity))
            .wrap(from_fn(oidc::sessions::resolve_session))
            .configure(sys::configure)
            .configure(metrics::configure)
            .configure(ui::configure)
            .configure(api::configure)
            .configure(oidc::handlers::configure)
            .default_service(web::to(not_found))
    })
    .bind(&bind)?
    .run()
    .await
}
