use actix_web::middleware::from_fn;
use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use tracing::{info, warn};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{EnvFilter, fmt};

mod middleware;
mod state;
mod sys;

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
    let shared_state = state::shared();

    match state::unseal_from_env(&shared_state).await {
        Ok(true) => info!("env-var unseal succeeded; vault is unsealed"),
        Ok(false) => info!("ANDVARI_ROOT_KEY not set; vault remains sealed"),
        Err(e) => {
            // Misconfigured ANDVARI_ROOT_KEY is operator error — fail loud at boot.
            warn!(error = %e, "env-var unseal failed; vault remains sealed");
        }
    }

    info!(%bind, "andvari-server starting");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(shared_state.clone()))
            .wrap(TracingLogger::default())
            .wrap(from_fn(middleware::require_unsealed))
            .configure(sys::configure)
            .default_service(web::to(not_found))
    })
    .bind(&bind)?
    .run()
    .await
}
