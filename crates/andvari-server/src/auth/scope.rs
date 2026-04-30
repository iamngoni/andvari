//! Scope policy attached to every service token.
//!
//! Scopes are **default deny**: a token may only do what its `ops` list
//! mentions, only against projects in `projects`, only against envs in
//! `envs`. The wildcard `"*"` (in either `projects` or `envs`) matches
//! anything within the token's workspace.

use serde::{Deserialize, Serialize};

/// Operations that scoped tokens can be granted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Read secret values.
    Read,
    /// Write secret values (create + update + delete).
    Write,
    /// Mint dynamic-secret leases.
    Lease,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
            Op::Lease => "lease",
        }
    }
}

/// What this token is allowed to do, where, and on what.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Scopes {
    /// Project slugs in the token's workspace, or `["*"]` for any.
    pub projects: Vec<String>,
    /// Environment names, or `["*"]` for any.
    pub envs: Vec<String>,
    /// Operations the token may perform.
    pub ops: Vec<Op>,
}

impl Scopes {
    /// Convenience constructor for read-only access to one project/env.
    pub fn read_one(project: impl Into<String>, env: impl Into<String>) -> Self {
        Self {
            projects: vec![project.into()],
            envs: vec![env.into()],
            ops: vec![Op::Read],
        }
    }

    /// Empty scope — useful as a default that allows nothing.
    pub fn empty() -> Self {
        Self {
            projects: Vec::new(),
            envs: Vec::new(),
            ops: Vec::new(),
        }
    }

    /// Whether this token may perform `op` on `(project, env)`.
    pub fn allows(&self, project: &str, env: &str, op: Op) -> bool {
        let project_ok = self.projects.iter().any(|p| p == "*" || p == project);
        let env_ok = self.envs.iter().any(|e| e == "*" || e == env);
        let op_ok = self.ops.contains(&op);
        project_ok && env_ok && op_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_allows() {
        let s = Scopes::read_one("spirit-finder", "dev");
        assert!(s.allows("spirit-finder", "dev", Op::Read));
    }

    #[test]
    fn op_default_deny() {
        let s = Scopes::read_one("spirit-finder", "dev");
        assert!(!s.allows("spirit-finder", "dev", Op::Write));
        assert!(!s.allows("spirit-finder", "dev", Op::Lease));
    }

    #[test]
    fn wrong_project_denied() {
        let s = Scopes::read_one("a", "dev");
        assert!(!s.allows("b", "dev", Op::Read));
    }

    #[test]
    fn wrong_env_denied() {
        let s = Scopes::read_one("a", "dev");
        assert!(!s.allows("a", "prod", Op::Read));
    }

    #[test]
    fn wildcard_project_matches_anything() {
        let s = Scopes {
            projects: vec!["*".into()],
            envs: vec!["dev".into()],
            ops: vec![Op::Read],
        };
        assert!(s.allows("anything", "dev", Op::Read));
        assert!(s.allows("else", "dev", Op::Read));
    }

    #[test]
    fn wildcard_env_matches_anything() {
        let s = Scopes {
            projects: vec!["a".into()],
            envs: vec!["*".into()],
            ops: vec![Op::Read],
        };
        assert!(s.allows("a", "any-env", Op::Read));
    }

    #[test]
    fn empty_scopes_deny_everything() {
        let s = Scopes::empty();
        assert!(!s.allows("a", "dev", Op::Read));
        assert!(!s.allows("a", "dev", Op::Write));
    }

    #[test]
    fn json_round_trip() {
        let s = Scopes {
            projects: vec!["a".into(), "b".into()],
            envs: vec!["dev".into()],
            ops: vec![Op::Read, Op::Write],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: Scopes = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
        // sanity: serde stores ops as lowercase strings.
        assert!(json.contains("\"read\""));
        assert!(json.contains("\"write\""));
    }
}
