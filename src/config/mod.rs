pub mod cli;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context};
use serde::Deserialize;
use time::OffsetDateTime;

/// Top-level service configuration document.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub version: u64,
    #[serde(default)]
    pub revision: Option<String>,
    /// Ask the client to refresh the configuration again no later than this time.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub valid_until: Option<OffsetDateTime>,
    /// Graceful period in seconds for the auth material in THIS config once it
    /// gets replaced by a newer config.
    #[serde(default)]
    pub graceful_period: Option<u64>,
    #[serde(default)]
    pub startup: StartupConfig,
    #[serde(default)]
    pub live: LiveConfig,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StartupConfig {
    pub stun: Option<StunFileConfig>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveConfig {
    #[serde(default)]
    pub auth: LiveAuthConfig,
    /// Webhook URL to call when STUN-discovered public address changes.
    /// Supports basic auth in URL: "https://user:pass@host/path"
    pub webhook_url: Option<String>,
    /// Metrics push configuration for remote-write to VictoriaMetrics / Prometheus.
    pub metrics_push: Option<MetricsPushFileConfig>,
}

#[derive(Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LiveAuthConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub sign_key: Option<String>,
    pub paths: Option<HashMap<String, PathAuthConfig>>,
}

/// Per-path authentication override.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum PathAuthConfig {
    Signature(SignatureSetting),
    Detailed { signature: Option<SignatureSetting> },
}

impl PathAuthConfig {
    pub fn signature(&self) -> Option<&SignatureSetting> {
        match self {
            Self::Signature(setting) => Some(setting),
            Self::Detailed { signature } => signature.as_ref(),
        }
    }
}

/// `false` = open download (no auth for GET), `true` = use global key, `"key"` = per-path key.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum SignatureSetting {
    Open(bool),
    Key(String),
}

/// STUN NAT traversal configuration from the config file.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StunFileConfig {
    /// Single STUN server address (backward compat), e.g. "stun.l.google.com:19302"
    pub server: Option<String>,
    /// Multiple STUN server addresses, e.g. ["stun.miwifi.com:3478", "stun.l.google.com:19302"]
    pub servers: Option<Vec<String>>,
    /// Keepalive interval in seconds (default: 20)
    pub interval_secs: Option<u64>,
}

impl StunFileConfig {
    /// Merge `server` (singular) and `servers` (plural) into a single list.
    /// `servers` takes precedence; if absent, `server` is treated as a single-element list.
    pub fn all_servers(&self) -> Vec<String> {
        if let Some(ref servers) = self.servers {
            servers.clone()
        } else if let Some(ref server) = self.server {
            vec![server.clone()]
        } else {
            vec![]
        }
    }
}

/// Metrics push configuration for remote-write to VictoriaMetrics / Prometheus.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricsPushFileConfig {
    /// Single push URL (backward compat), e.g. "http://user:pass@vm:8428/api/v1/import/prometheus"
    pub url: Option<String>,
    /// Multiple push URLs
    pub urls: Option<Vec<String>>,
    /// Push interval in seconds (default: 15)
    pub interval_secs: Option<u64>,
}

impl MetricsPushFileConfig {
    /// Merge `url` (singular) and `urls` (plural) into a single list.
    pub fn all_urls(&self) -> Vec<String> {
        if let Some(ref urls) = self.urls {
            urls.clone()
        } else if let Some(ref url) = self.url {
            vec![url.clone()]
        } else {
            vec![]
        }
    }
}

/// Parse and validate a YAML service configuration document.
pub fn parse_config_str(content: &str, source: &str) -> anyhow::Result<ServiceConfig> {
    let config: ServiceConfig = serde_yaml::from_str(content)
        .with_context(|| format!("Failed to parse config: {source}"))?;

    validate_config(config)
}

/// Load and validate a YAML configuration file.
pub fn load_config(path: &Path) -> anyhow::Result<ServiceConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    parse_config_str(&content, &path.display().to_string())
}

fn validate_config(config: ServiceConfig) -> anyhow::Result<ServiceConfig> {
    // Validate version
    if config.version != 2 {
        bail!(
            "Unsupported config version: {}. Only version 2 is supported.",
            config.version
        );
    }

    // Validate username/password pairing
    if config.live.auth.username.is_some() != config.live.auth.password.is_some() {
        bail!(
            "Config error: 'live.auth.username' and 'live.auth.password' must both be set or both omitted"
        );
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::{parse_config_str, SignatureSetting};

    #[test]
    fn parses_service_config_with_path_shortcuts() {
        let yaml = r#"
version: 2
valid_until: 2026-03-20T16:05:00Z
graceful_period: 900
startup:
  stun:
    servers:
      - stun.l.google.com:19302
live:
  auth:
    username: uploader
    password: secret
    paths:
      /public: false
      /protected: true
      /special: deadbeef
"#;

        let config = parse_config_str(yaml, "inline-test").expect("config should parse");
        let paths = config.live.auth.paths.expect("paths should exist");

        assert_eq!(
            paths.get("/public").and_then(|path| path.signature()),
            Some(&SignatureSetting::Open(false))
        );
        assert_eq!(
            paths.get("/protected").and_then(|path| path.signature()),
            Some(&SignatureSetting::Open(true))
        );
        assert_eq!(
            paths.get("/special").and_then(|path| path.signature()),
            Some(&SignatureSetting::Key("deadbeef".to_string()))
        );
        assert_eq!(config.graceful_period, Some(900));
        assert!(config.valid_until.is_some());
    }
}
