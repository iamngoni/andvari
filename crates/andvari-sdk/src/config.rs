//! Layered configuration resolver.
//!
//! Precedence (highest → lowest):
//!
//! 1. CLI flag overrides passed via [`ResolveOptions::overrides`]
//! 2. `ANDVARI_*` environment variables
//! 3. Nearest `andvari.toml`, walking up from `cwd` like `cargo` / `git`
//! 4. `~/.config/andvari/config.toml` (per-user defaults)
//! 5. Built-in defaults (everything `None`)
//!
//! Everything in the file is optional — a layer that doesn't set a field
//! leaves it for a lower-priority layer to fill in.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("figment: {0}")]
    Figment(#[from] figment::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// User-facing config. Every field is optional so layers compose cleanly.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub server: Option<String>,
    pub workspace: Option<String>,
    pub project: Option<String>,
    pub default_env: Option<String>,
    /// Optional list of known envs for tab-completion / validation.
    pub envs: Option<Vec<String>>,
    /// Per-environment overrides keyed by env name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, EnvOverride>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvOverride {
    /// If true, this env refuses static service tokens — must use OIDC
    /// federation. Useful for production envs where you don't want any
    /// long-lived credentials in CI.
    pub require_oidc_federation: Option<bool>,
}

/// Inputs to the resolver — typically the parsed CLI flags.
#[derive(Debug, Clone, Default)]
pub struct ResolveOptions {
    /// Override the cwd used for the upward `andvari.toml` walk.
    /// `None` means use `std::env::current_dir`.
    pub start_dir: Option<PathBuf>,
    /// Override the user-config path (defaults to `dirs::config_dir() / andvari / config.toml`).
    pub user_config_path: Option<PathBuf>,
    /// CLI flag overrides (highest priority).
    pub overrides: Config,
}

impl Config {
    /// Resolve the layered configuration.
    pub fn resolve(opts: ResolveOptions) -> Result<Self, ConfigError> {
        let user_path = opts
            .user_config_path
            .or_else(default_user_config_path);

        let start = match opts.start_dir {
            Some(p) => p,
            None => std::env::current_dir()?,
        };
        let repo_path = find_repo_config(&start);

        let mut figment = Figment::new();

        if let Some(user) = user_path.as_ref() {
            if user.exists() {
                figment = figment.merge(Toml::file_exact(user));
            }
        }
        if let Some(repo) = repo_path.as_ref() {
            figment = figment.merge(Toml::file_exact(repo));
        }
        // ANDVARI_SERVER, ANDVARI_WORKSPACE, ANDVARI_PROJECT, ANDVARI_DEFAULT_ENV.
        figment = figment.merge(Env::prefixed("ANDVARI_").only(&[
            "server",
            "workspace",
            "project",
            "default_env",
        ]));

        let mut config: Config = figment.extract()?;

        // Apply CLI overrides last — they win over everything.
        config.merge(opts.overrides);

        Ok(config)
    }

    /// Apply non-`None` fields from `other` on top of `self`.
    pub fn merge(&mut self, other: Config) {
        if other.server.is_some() {
            self.server = other.server;
        }
        if other.workspace.is_some() {
            self.workspace = other.workspace;
        }
        if other.project.is_some() {
            self.project = other.project;
        }
        if other.default_env.is_some() {
            self.default_env = other.default_env;
        }
        if other.envs.is_some() {
            self.envs = other.envs;
        }
        for (k, v) in other.env {
            self.env.insert(k, v);
        }
    }
}

fn default_user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("andvari").join("config.toml"))
}

fn find_repo_config(start: &Path) -> Option<PathBuf> {
    for ancestor in start.ancestors() {
        let candidate = ancestor.join("andvari.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn isolated_resolve(
        start_dir: &Path,
        user_path: Option<&Path>,
    ) -> Result<Config, ConfigError> {
        // Avoid stomping on the real user's environment for these tests.
        for var in ["ANDVARI_SERVER", "ANDVARI_WORKSPACE", "ANDVARI_PROJECT", "ANDVARI_DEFAULT_ENV"] {
            unsafe { std::env::remove_var(var) };
        }
        Config::resolve(ResolveOptions {
            start_dir: Some(start_dir.to_path_buf()),
            user_config_path: user_path.map(Path::to_path_buf),
            overrides: Config::default(),
        })
    }

    #[test]
    fn empty_dir_yields_empty_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = isolated_resolve(tmp.path(), Some(&tmp.path().join("nonexistent.toml")))
            .unwrap();
        assert_eq!(cfg, Config::default());
    }

    #[test]
    fn andvari_toml_in_dir_is_picked_up() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("andvari.toml"),
            r#"
            server = "https://andvari.example.com"
            workspace = "spirit-finder"
            project = "spirit-finder"
            default_env = "dev"
            "#,
        )
        .unwrap();

        let cfg = isolated_resolve(tmp.path(), None).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("https://andvari.example.com"));
        assert_eq!(cfg.workspace.as_deref(), Some("spirit-finder"));
        assert_eq!(cfg.default_env.as_deref(), Some("dev"));
    }

    #[test]
    fn andvari_toml_walks_up_from_subdir() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("andvari.toml"), r#"workspace = "from-root""#).unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();

        let cfg = isolated_resolve(&nested, None).unwrap();
        assert_eq!(cfg.workspace.as_deref(), Some("from-root"));
    }

    #[test]
    fn user_config_provides_defaults() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp.path().join("user.toml");
        fs::write(&user, r#"server = "https://shared.example""#).unwrap();
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();

        let cfg = isolated_resolve(&work, Some(&user)).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("https://shared.example"));
    }

    #[test]
    fn repo_config_overrides_user_config() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp.path().join("user.toml");
        fs::write(&user, r#"server = "user-default""#).unwrap();
        let work = tmp.path().join("work");
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("andvari.toml"), r#"server = "from-repo""#).unwrap();

        let cfg = isolated_resolve(&work, Some(&user)).unwrap();
        assert_eq!(cfg.server.as_deref(), Some("from-repo"));
    }

    #[test]
    fn cli_overrides_win() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("andvari.toml"), r#"server = "from-repo""#).unwrap();

        let cfg = Config::resolve(ResolveOptions {
            start_dir: Some(tmp.path().to_path_buf()),
            user_config_path: Some(tmp.path().join("nope.toml")),
            overrides: Config {
                server: Some("from-flag".into()),
                ..Config::default()
            },
        })
        .unwrap();
        assert_eq!(cfg.server.as_deref(), Some("from-flag"));
    }

    #[test]
    fn merge_preserves_self_for_missing_fields() {
        let mut a = Config {
            server: Some("a".into()),
            workspace: Some("ws-a".into()),
            ..Default::default()
        };
        let b = Config {
            server: Some("b".into()),
            ..Default::default()
        };
        a.merge(b);
        assert_eq!(a.server.as_deref(), Some("b"));
        assert_eq!(a.workspace.as_deref(), Some("ws-a")); // untouched
    }

    #[test]
    fn per_env_overrides_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("andvari.toml"),
            r#"
            server = "x"

            [env.prod]
            require_oidc_federation = true
            "#,
        )
        .unwrap();
        let cfg = isolated_resolve(tmp.path(), None).unwrap();
        let prod = cfg.env.get("prod").unwrap();
        assert_eq!(prod.require_oidc_federation, Some(true));
    }
}
