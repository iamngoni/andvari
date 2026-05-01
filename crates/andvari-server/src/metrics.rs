//! Prometheus metrics surface.
//!
//! Exposed at `GET /metrics` in the standard text exposition format. Counters
//! increment from the secret/auth handlers; gauges sit on long-lived state
//! (currently `andvari_vault_sealed`).

use actix_web::{HttpResponse, Responder, get, web};
use once_cell::sync::Lazy;
use prometheus::{
    Encoder, IntCounterVec, IntGauge, Registry, TextEncoder,
    register_int_counter_vec_with_registry, register_int_gauge_with_registry,
};

use crate::state::AppState;

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static SECRET_OPS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "andvari_secret_ops_total",
        "Count of secret operations",
        &["op", "outcome"],
        REGISTRY
    )
    .expect("register andvari_secret_ops_total")
});

pub static AUTH_EVENTS: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec_with_registry!(
        "andvari_auth_events_total",
        "Count of authentication events",
        &["kind", "outcome"],
        REGISTRY
    )
    .expect("register andvari_auth_events_total")
});

pub static VAULT_SEALED: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge_with_registry!(
        "andvari_vault_sealed",
        "1 when the vault is sealed, 0 when unsealed",
        REGISTRY
    )
    .expect("register andvari_vault_sealed")
});

pub fn record_secret_op(op: &str, outcome: &str) {
    SECRET_OPS.with_label_values(&[op, outcome]).inc();
}

pub fn record_auth_event(kind: &str, outcome: &str) {
    AUTH_EVENTS.with_label_values(&[kind, outcome]).inc();
}

pub fn set_sealed(sealed: bool) {
    VAULT_SEALED.set(if sealed { 1 } else { 0 });
}

#[get("/metrics")]
async fn metrics_handler(state: web::Data<AppState>) -> impl Responder {
    // Refresh the sealed gauge each scrape so it reflects current state.
    let sealed = state.vault.read().await.is_sealed();
    set_sealed(sealed);

    let metric_families = REGISTRY.gather();
    let mut buf = Vec::new();
    if TextEncoder::new().encode(&metric_families, &mut buf).is_err() {
        return HttpResponse::InternalServerError().body("encode failed");
    }
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(buf)
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(metrics_handler);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_increment() {
        let before = SECRET_OPS.with_label_values(&["read", "ok"]).get();
        record_secret_op("read", "ok");
        record_secret_op("read", "ok");
        let after = SECRET_OPS.with_label_values(&["read", "ok"]).get();
        assert_eq!(after - before, 2);
    }

    #[test]
    fn vault_sealed_gauge_toggles() {
        set_sealed(true);
        assert_eq!(VAULT_SEALED.get(), 1);
        set_sealed(false);
        assert_eq!(VAULT_SEALED.get(), 0);
    }

    #[test]
    fn registry_renders_prometheus_text() {
        record_secret_op("write", "ok");
        let metric_families = REGISTRY.gather();
        let mut buf = Vec::new();
        TextEncoder::new().encode(&metric_families, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("andvari_secret_ops_total"));
        assert!(text.contains("# TYPE"));
    }
}
