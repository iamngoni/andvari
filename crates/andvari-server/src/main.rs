use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use tracing::info;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::{EnvFilter, fmt};

#[get("/v1/sys/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "sealed": true,
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn sealed_503() -> impl Responder {
    HttpResponse::ServiceUnavailable().json(serde_json::json!({
        "error": "vault is sealed",
    }))
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
    info!(%bind, "andvari-server starting");

    HttpServer::new(|| {
        App::new()
            .wrap(TracingLogger::default())
            .service(health)
            .default_service(web::to(sealed_503))
    })
    .bind(&bind)?
    .run()
    .await
}
