pub mod cli;

use std::collections::HashMap;
use std::path::Path;

use anyhow::{bail, Context};
use serde::Deserialize;

/// Top-level YAML configuration file.
#[derive(Deserialize, Debug)]
pub struct FileConfig {
    pub version: u64,
    pub username: Option<String>,
    pub password: Option<String>,
    pub sign_key: Option<String>,
    pub paths: Option<HashMap<String, PathAuthConfig>>,
    pub tus: Option<TusFileConfig>,
    pub stun: Option<StunFileConfig>,
    /// Webhook URL to call when STUN-discovered public address changes.
    /// Supports basic auth in URL: "https://user:pass@host/path"
    pub webhook_url: Option<String>,
    /// Metrics push configuration for remote-write to VictoriaMetrics / Prometheus.
    pub metrics_push: Option<MetricsPushFileConfig>,
}

/// Per-path authentication override.
#[derive(Deserialize, Debug, Clone)]
pub struct PathAuthConfig {
    pub signature: Option<SignatureSetting>,
}

/// `false` = open download (no auth for GET), `true` = use global key, `"key"` = per-path key.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum SignatureSetting {
    Open(bool),
    Key(String),
}

/// TUS resumable upload configuration from the config file.
#[derive(Deserialize, Debug, Clone)]
pub struct TusFileConfig {
    pub enabled: Option<bool>,
    pub temp_dir: Option<String>,
    pub upload_timeout_hours: Option<u64>,
    pub max_concurrent_uploads: Option<usize>,
    pub max_upload_size: Option<u64>,
}

/// STUN NAT traversal configuration from the config file.
#[derive(Deserialize, Debug, Clone)]
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
#[derive(Deserialize, Debug, Clone)]
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

/// Load and validate a YAML configuration file.
pub fn load_config(path: &Path) -> anyhow::Result<FileConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let config: FileConfig = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    // Validate version
    if config.version != 1 {
        bail!(
            "Unsupported config version: {}. Only version 1 is supported.",
            config.version
        );
    }

    // Validate username/password pairing
    if config.username.is_some() != config.password.is_some() {
        bail!("Config error: 'username' and 'password' must both be set or both omitted");
    }

    Ok(config)
}
