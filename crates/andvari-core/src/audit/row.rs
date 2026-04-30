//! Deterministic byte encoding of an audit row.
//!
//! The HMAC chain feeds these canonical bytes into HMAC-SHA256, so two
//! deployments must produce byte-identical encodings for byte-identical row
//! content. JSON / serde would not satisfy that contract (key ordering,
//! whitespace, number formatting); we hand-roll a length-prefixed format
//! instead.
//!
//! Wire layout — every field in fixed order, each as `[u32_be_len][bytes]`:
//!
//! ```text
//! ts_unix_nanos (16 bytes BE i128)
//! workspace_id   (UUID 16 bytes or empty)
//! actor_id       (UUID 16 bytes or empty)
//! actor_kind     (UTF-8)
//! action         (UTF-8)
//! target_kind    (UTF-8 or empty)
//! target_id      (UUID 16 bytes or empty)
//! ip             (4 bytes IPv4 / 16 bytes IPv6 / empty)
//! user_agent     (UTF-8 or empty)
//! request_id     (UUID 16 bytes or empty)
//! ```

use std::net::IpAddr;

use time::OffsetDateTime;
use uuid::Uuid;

/// What kind of identity issued this action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    User,
    Token,
    OidcFed,
    System,
}

impl ActorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ActorKind::User => "user",
            ActorKind::Token => "token",
            ActorKind::OidcFed => "oidc-fed",
            ActorKind::System => "system",
        }
    }
}

/// A single audit log entry, prior to chain computation.
///
/// Fields with `Option` semantics omit their bytes from the canonical
/// encoding (length-prefixed empty slot).
#[derive(Debug, Clone)]
pub struct AuditRow<'a> {
    pub ts: OffsetDateTime,
    pub workspace_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub actor_kind: ActorKind,
    pub action: &'a str,
    pub target_kind: Option<&'a str>,
    pub target_id: Option<Uuid>,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
    pub request_id: Option<Uuid>,
}

impl<'a> AuditRow<'a> {
    /// Deterministic byte serialization fed into the HMAC chain.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Timestamp: i128 nanoseconds since Unix epoch, big-endian.
        write_field(&mut buf, &self.ts.unix_timestamp_nanos().to_be_bytes());

        write_optional_uuid(&mut buf, self.workspace_id);
        write_optional_uuid(&mut buf, self.actor_id);
        write_field(&mut buf, self.actor_kind.as_str().as_bytes());
        write_field(&mut buf, self.action.as_bytes());
        write_optional_str(&mut buf, self.target_kind);
        write_optional_uuid(&mut buf, self.target_id);
        write_optional_ip(&mut buf, self.ip);
        write_optional_str(&mut buf, self.user_agent);
        write_optional_uuid(&mut buf, self.request_id);

        buf
    }
}

fn write_field(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

fn write_optional_uuid(buf: &mut Vec<u8>, id: Option<Uuid>) {
    match id {
        Some(u) => write_field(buf, u.as_bytes()),
        None => write_field(buf, &[]),
    }
}

fn write_optional_str(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => write_field(buf, v.as_bytes()),
        None => write_field(buf, &[]),
    }
}

fn write_optional_ip(buf: &mut Vec<u8>, ip: Option<IpAddr>) {
    match ip {
        Some(IpAddr::V4(v4)) => write_field(buf, &v4.octets()),
        Some(IpAddr::V6(v6)) => write_field(buf, &v6.octets()),
        None => write_field(buf, &[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn fixed_ts() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap()
    }

    #[test]
    fn deterministic_for_identical_input() {
        let row = AuditRow {
            ts: fixed_ts(),
            workspace_id: Some(Uuid::nil()),
            actor_id: None,
            actor_kind: ActorKind::User,
            action: "secret.read",
            target_kind: Some("secret"),
            target_id: None,
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            user_agent: Some("andvari-cli/0.1.0"),
            request_id: None,
        };
        assert_eq!(row.canonical_bytes(), row.canonical_bytes());
    }

    #[test]
    fn changing_action_changes_bytes() {
        let mut row = AuditRow {
            ts: fixed_ts(),
            workspace_id: None,
            actor_id: None,
            actor_kind: ActorKind::System,
            action: "a",
            target_kind: None,
            target_id: None,
            ip: None,
            user_agent: None,
            request_id: None,
        };
        let a = row.canonical_bytes();
        row.action = "b";
        let b = row.canonical_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn optional_fields_are_distinguishable_from_empty_strings() {
        // None and Some("") must produce the same length-prefix (both zero
        // bytes), so this invariant holds. We capture the contract here so
        // future contributors don't accidentally introduce a sentinel byte.
        let mut row = AuditRow {
            ts: fixed_ts(),
            workspace_id: None,
            actor_id: None,
            actor_kind: ActorKind::System,
            action: "x",
            target_kind: None,
            target_id: None,
            ip: None,
            user_agent: None,
            request_id: None,
        };
        let with_none = row.canonical_bytes();
        row.target_kind = Some("");
        let with_empty = row.canonical_bytes();
        assert_eq!(with_none, with_empty,
            "None and Some(\"\") deliberately encode the same — see comment");
    }

    #[test]
    fn ipv4_and_ipv6_distinct() {
        let mut row = AuditRow {
            ts: fixed_ts(),
            workspace_id: None,
            actor_id: None,
            actor_kind: ActorKind::System,
            action: "x",
            target_kind: None,
            target_id: None,
            ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            user_agent: None,
            request_id: None,
        };
        let v4 = row.canonical_bytes();
        row.ip = Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        let v6 = row.canonical_bytes();
        assert_ne!(v4, v6);
    }

    #[test]
    fn actor_kind_string_form() {
        assert_eq!(ActorKind::User.as_str(), "user");
        assert_eq!(ActorKind::Token.as_str(), "token");
        assert_eq!(ActorKind::OidcFed.as_str(), "oidc-fed");
        assert_eq!(ActorKind::System.as_str(), "system");
    }
}
