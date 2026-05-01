//! SPIRE / SPIFFE workload identity integration.
//!
//! Andvari deliberately doesn't ship its own internal CA or mTLS terminator —
//! per the spec, "defer to SPIRE rather than reimplementing internal CA infra."
//! Instead, this module supports the standard deployment pattern where a
//! sidecar (Envoy, Istio, NGINX, Linkerd) terminates mTLS using SPIFFE SVIDs
//! and forwards the verified peer identity to Andvari over the loopback
//! connection in a header.
//!
//! Configuration:
//! - `ANDVARI_SPIFFE_TRUST_DOMAIN` — accepted trust domain (e.g. `example.org`).
//! - `ANDVARI_SPIFFE_HEADER` — header name carrying the peer SPIFFE ID
//!   (default: `X-SPIFFE-ID`). Set to `X-Forwarded-Client-Cert` if your
//!   sidecar emits the Envoy XFCC format; we parse the `URI=` field there.
//!
//! When configured, requests arriving without a recognized SPIFFE ID from the
//! configured trust domain are tagged but NOT rejected here — route handlers
//! decide what to do. This module just exposes [`PeerSpiffeId`] for handlers
//! to read out of `req.extensions()`.

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;
use actix_web::{Error, HttpMessage};
use once_cell::sync::OnceCell;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSpiffeId {
    pub raw: String,
    pub trust_domain: String,
    pub path: String,
}

impl PeerSpiffeId {
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim().trim_matches('"');
        let rest = trimmed.strip_prefix("spiffe://")?;
        let (td, path) = rest.split_once('/').unwrap_or((rest, ""));
        if td.is_empty() {
            return None;
        }
        Some(Self {
            raw: trimmed.to_string(),
            trust_domain: td.to_string(),
            path: path.to_string(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct SpireConfig {
    pub trust_domain: String,
    pub header: String,
}

static SPIRE_CONFIG: OnceCell<SpireConfig> = OnceCell::new();

pub fn init_from_env() -> Option<&'static SpireConfig> {
    let trust_domain = std::env::var("ANDVARI_SPIFFE_TRUST_DOMAIN").ok()?;
    let header = std::env::var("ANDVARI_SPIFFE_HEADER")
        .unwrap_or_else(|_| "X-SPIFFE-ID".to_string());
    let cfg = SpireConfig {
        trust_domain,
        header,
    };
    let _ = SPIRE_CONFIG.set(cfg);
    SPIRE_CONFIG.get()
}

/// Try to extract a SPIFFE ID from the configured header. Handles both
/// plain `spiffe://...` values and Envoy's XFCC `URI=spiffe://...` format.
fn extract_spiffe(header_value: &str) -> Option<PeerSpiffeId> {
    if let Some(id) = PeerSpiffeId::parse(header_value) {
        return Some(id);
    }
    // XFCC: `URI=spiffe://td/path;Hash=...;...`
    for part in header_value.split([';', ',']) {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("URI=") {
            if let Some(id) = PeerSpiffeId::parse(value) {
                return Some(id);
            }
        }
    }
    None
}

/// Middleware: parse the configured header, attach [`PeerSpiffeId`] to
/// extensions if it matches the configured trust domain.
pub async fn resolve_peer<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<B>, Error>
where
    B: MessageBody + 'static,
{
    if let Some(cfg) = SPIRE_CONFIG.get() {
        if let Some(value) = req.headers().get(cfg.header.as_str()) {
            if let Ok(s) = value.to_str() {
                if let Some(id) = extract_spiffe(s) {
                    if id.trust_domain == cfg.trust_domain {
                        req.extensions_mut().insert(id);
                    }
                }
            }
        }
    }
    next.call(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spiffe_id() {
        let id = PeerSpiffeId::parse("spiffe://example.org/ns/default/sa/spirit-finder").unwrap();
        assert_eq!(id.trust_domain, "example.org");
        assert_eq!(id.path, "ns/default/sa/spirit-finder");
    }

    #[test]
    fn parse_spiffe_id_with_quotes() {
        let id = PeerSpiffeId::parse("\"spiffe://td/foo\"").unwrap();
        assert_eq!(id.trust_domain, "td");
    }

    #[test]
    fn parse_rejects_non_spiffe() {
        assert!(PeerSpiffeId::parse("https://example.org/foo").is_none());
        assert!(PeerSpiffeId::parse("spiffe://").is_none());
    }

    #[test]
    fn extract_from_xfcc() {
        let xfcc = "By=spiffe://example.org/ingress;Hash=abc123;URI=spiffe://example.org/ns/default/sa/svc";
        let id = extract_spiffe(xfcc).unwrap();
        assert_eq!(id.path, "ns/default/sa/svc");
    }

    #[test]
    fn extract_plain_header() {
        let id = extract_spiffe("spiffe://example.org/foo").unwrap();
        assert_eq!(id.path, "foo");
    }
}
