//! `/v1/sys/*` endpoints — the small set of routes that work even when the
//! vault is sealed.

use actix_web::{HttpResponse, Responder, get, post, web};
use andvari_core::VaultState;
use andvari_core::seal::SubmitOutcome;
use andvari_core::seal::shamir::decode_share;
use serde::Deserialize;
use tracing::warn;

use crate::state::AppState;

#[get("/v1/sys/health")]
pub async fn health(state: web::Data<AppState>) -> impl Responder {
    let sealed = state.vault.read().await.is_sealed();
    let unseal_progress = state.unseal.read().await;
    let unseal_info = unseal_progress.as_ref().map(|p| {
        serde_json::json!({
            "received": p.received(),
            "threshold": p.threshold(),
        })
    });
    drop(unseal_progress);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "sealed": sealed,
        "version": env!("CARGO_PKG_VERSION"),
        "unseal": unseal_info,
    }))
}

#[post("/v1/sys/seal")]
pub async fn seal(state: web::Data<AppState>) -> impl Responder {
    // TODO: require an admin/owner identity. Auth lands in a later slice.
    let mut vault = state.vault.write().await;
    vault.seal();
    drop(vault);

    // Re-initialize the Shamir progress for the next unseal attempt, if Shamir
    // mode is active.
    if let Some(p) = state.unseal.write().await.as_mut() {
        p.clear();
    }

    HttpResponse::Ok().json(serde_json::json!({ "sealed": true }))
}

#[derive(Deserialize)]
pub struct UnsealRequest {
    /// Base64-encoded Shamir share (33 bytes raw).
    pub share: String,
}

#[post("/v1/sys/unseal")]
pub async fn unseal(state: web::Data<AppState>, body: web::Json<UnsealRequest>) -> impl Responder {
    if !state.vault.read().await.is_sealed() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "vault is already unsealed",
        }));
    }

    let share_bytes = match decode_share(&body.share) {
        Ok(b) => b,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid share",
                "detail": e.to_string(),
            }));
        }
    };

    let mut progress_guard = state.unseal.write().await;
    let Some(progress) = progress_guard.as_mut() else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "shamir unseal mode not configured",
            "hint": "set ANDVARI_SHAMIR_THRESHOLD on the server, or use ANDVARI_ROOT_KEY for env-var unseal",
        }));
    };

    let outcome = match progress.submit(share_bytes) {
        Ok(o) => o,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "share rejected",
                "detail": e.to_string(),
            }));
        }
    };

    match outcome {
        SubmitOutcome::Accepted {
            received,
            threshold,
        }
        | SubmitOutcome::Duplicate {
            received,
            threshold,
        } => HttpResponse::Ok().json(serde_json::json!({
            "sealed": true,
            "received": received,
            "threshold": threshold,
            "duplicate": matches!(outcome, SubmitOutcome::Duplicate { .. }),
        })),
        SubmitOutcome::Threshold {
            received,
            threshold,
        } => {
            // We have enough material — try to reconstruct.
            match progress.reconstruct() {
                Ok(rk) => {
                    progress.clear();
                    drop(progress_guard);
                    *state.vault.write().await = VaultState::unsealed(rk);
                    HttpResponse::Ok().json(serde_json::json!({
                        "sealed": false,
                        "received": received,
                        "threshold": threshold,
                    }))
                }
                Err(e) => {
                    warn!(error = %e, "shamir reconstruction failed; clearing progress");
                    progress.clear();
                    HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "shamir reconstruction failed; resubmit shares",
                        "detail": e.to_string(),
                    }))
                }
            }
        }
    }
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(health).service(seal).service(unseal);
}

#[cfg(test)]
mod tests {
    use actix_web::{App, test, web};
    use andvari_core::crypto::RootKey;
    use andvari_core::seal::UnsealProgress;
    use andvari_core::seal::shamir::split_root_key_base64;

    use crate::state::AppState;

    fn app_with_state(
        state: AppState,
    ) -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        App::new()
            .app_data(web::Data::new(state))
            .configure(super::configure)
    }

    #[actix_web::test]
    async fn health_reports_sealed_state() {
        let app = app_with_state(AppState::new());
        let svc = test::init_service(app).await;
        let req = test::TestRequest::get().uri("/v1/sys/health").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&svc, req).await;
        assert_eq!(body["sealed"], true);
        assert_eq!(body["status"], "ok");
    }

    #[actix_web::test]
    async fn unseal_without_progress_is_400() {
        let app = app_with_state(AppState::new());
        let svc = test::init_service(app).await;
        let req = test::TestRequest::post()
            .uri("/v1/sys/unseal")
            .set_json(serde_json::json!({ "share": "AAAA" }))
            .to_request();
        let resp = test::call_service(&svc, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn shamir_unseal_handshake_e2e() {
        // Build a known RK, split it 3-of-5, install a fresh progress, then
        // POST shares one at a time and assert the final transition.
        let rk = RootKey::from_bytes([0x33u8; 32]);
        let shares = split_root_key_base64(&rk, 3, 5).unwrap();

        let state = AppState::new();
        *state.unseal.write().await = Some(UnsealProgress::new(3));

        let app = app_with_state(state.clone());
        let svc = test::init_service(app).await;

        for (i, share) in shares.iter().take(2).enumerate() {
            let req = test::TestRequest::post()
                .uri("/v1/sys/unseal")
                .set_json(serde_json::json!({ "share": share }))
                .to_request();
            let body: serde_json::Value = test::call_and_read_body_json(&svc, req).await;
            assert_eq!(body["sealed"], true);
            assert_eq!(body["received"], (i + 1) as u64);
        }

        // Third share crosses the threshold and unseals.
        let req = test::TestRequest::post()
            .uri("/v1/sys/unseal")
            .set_json(serde_json::json!({ "share": shares[2] }))
            .to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&svc, req).await;
        assert_eq!(body["sealed"], false);

        // Vault state must reflect unsealed (byte-level RK correctness is
        // covered by andvari-core's split/combine unit tests).
        assert!(!state.vault.read().await.is_sealed());
        assert!(state.vault.read().await.root_key().is_some());
    }

    #[actix_web::test]
    async fn duplicate_share_does_not_advance_progress() {
        let rk = RootKey::generate();
        let shares = split_root_key_base64(&rk, 3, 5).unwrap();

        let state = AppState::new();
        *state.unseal.write().await = Some(UnsealProgress::new(3));

        let app = app_with_state(state);
        let svc = test::init_service(app).await;

        // Submit first share, then submit it again. Progress must stay at 1.
        let r1 = test::TestRequest::post()
            .uri("/v1/sys/unseal")
            .set_json(serde_json::json!({ "share": shares[0] }))
            .to_request();
        let b1: serde_json::Value = test::call_and_read_body_json(&svc, r1).await;
        assert_eq!(b1["received"], 1);

        let r2 = test::TestRequest::post()
            .uri("/v1/sys/unseal")
            .set_json(serde_json::json!({ "share": shares[0] }))
            .to_request();
        let b2: serde_json::Value = test::call_and_read_body_json(&svc, r2).await;
        assert_eq!(b2["received"], 1);
        assert_eq!(b2["duplicate"], true);
    }

    #[actix_web::test]
    async fn malformed_share_is_400() {
        let state = AppState::new();
        *state.unseal.write().await = Some(UnsealProgress::new(3));

        let app = app_with_state(state);
        let svc = test::init_service(app).await;

        // Not even valid base64.
        let req = test::TestRequest::post()
            .uri("/v1/sys/unseal")
            .set_json(serde_json::json!({ "share": "$$$" }))
            .to_request();
        let resp = test::call_service(&svc, req).await;
        assert_eq!(resp.status(), 400);
    }

    #[actix_web::test]
    async fn seal_endpoint_re_seals_unsealed_vault() {
        use andvari_core::VaultState;

        let state = AppState::new();
        *state.vault.write().await = VaultState::unsealed(RootKey::generate());

        let app = app_with_state(state.clone());
        let svc = test::init_service(app).await;

        let req = test::TestRequest::post().uri("/v1/sys/seal").to_request();
        let body: serde_json::Value = test::call_and_read_body_json(&svc, req).await;
        assert_eq!(body["sealed"], true);
        assert!(state.vault.read().await.is_sealed());
    }
}
