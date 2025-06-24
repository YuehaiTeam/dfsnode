use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use arc_swap::ArcSwap;
use radix_trie::Trie;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::metrics::CONFIG_VERSION;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathConfig {
    pub autoindex: Option<bool>,
    pub signature: Option<String>,
    pub signature_expire_seconds: Option<u32>, // 签名过期时间，默认3600秒(1小时)
}

#[derive(Debug, Clone)]
pub struct OptimizedConfig {
    pub version: u64,
    pub path_trie: Trie<String, PathConfig>,
    pub prometheus_auth_header: Option<String>, // 预计算的认证头
}

impl Default for OptimizedConfig {
    fn default() -> Self {
        Self {
            version: 0,
            path_trie: Trie::new(),
            prometheus_auth_header: None,
        }
    }
}

impl OptimizedConfig {
    pub fn from_config(config: Config) -> Self {
        let mut path_trie = Trie::new();

        // 将路径配置插入前缀树
        for (path, path_config) in &config.paths {
            path_trie.insert(path.clone(), path_config.clone());
        }

        // 预计算 Prometheus 认证头
        let prometheus_auth_header = config
            .prometheus_token
            .as_ref()
            .map(|token| format!("Bearer {}", token));

        Self {
            version: config.version.unwrap_or(0),
            path_trie,
            prometheus_auth_header,
        }
    }

    pub fn find_path_config(&self, path: &str) -> Option<&PathConfig> {
        // 使用前缀树查找最长匹配的路径
        self.path_trie.get_ancestor_value(path)
    }

    pub fn get_version(&self) -> u64 {
        self.version
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub version: Option<u64>,
    pub paths: HashMap<String, PathConfig>,
    pub prometheus_token: Option<String>,
}

pub async fn load_config_from_file(
    config: &Arc<ArcSwap<OptimizedConfig>>,
    config_path: &str,
) -> Result<()> {
    let content = tokio::fs::read_to_string(config_path).await?;
    let config_data: Config = serde_yml::from_str(&content)?;
    let optimized_config = OptimizedConfig::from_config(config_data.clone());
    let version = config_data.version.unwrap_or(0);

    config.store(Arc::new(optimized_config));

    // 更新配置版本指标
    CONFIG_VERSION.set(version);

    info!(
        "Loaded config from file: {} (version: {})",
        config_path, version
    );
    Ok(())
}

pub async fn load_config_from_central(
    config: &Arc<ArcSwap<OptimizedConfig>>,
    central_url: &str,
    server_id: Option<&str>,
    auth_header: Option<&str>,
    http_client: &reqwest::Client,
) -> Result<()> {
    let config_url = if let Some(id) = server_id {
        format!("{}/{}/config", central_url, id)
    } else {
        format!("{}/config", central_url)
    };

    let mut request = http_client.get(&config_url);

    if let Some(auth) = auth_header {
        request = request.header("Authorization", auth);
    }

    let response = request.send().await?;
    let config_text = response.text().await?;
    let config_data: Config = serde_yml::from_str(&config_text)?;

    let new_version = config_data.version.unwrap_or(0);
    let current_version = config.load().get_version();

    // 仅在版本号更新时才解析并替换配置
    if new_version != current_version {
        let optimized_config = OptimizedConfig::from_config(config_data);

        config.store(Arc::new(optimized_config));

        // 更新配置版本指标
        CONFIG_VERSION.set(new_version);

        info!(
            "Updated config from central server (version: {} -> {})",
            current_version, new_version
        );
    } else {
        info!(
            "Config version unchanged ({}), skipping update",
            current_version
        );
    }

    Ok(())
}

pub async fn config_refresh_task(
    config: Arc<ArcSwap<OptimizedConfig>>,
    central_url: String,
    server_id: Option<String>,
    auth_header: Option<String>,
    http_client: reqwest::Client,
) {
    let mut interval = interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        if let Err(e) = load_config_from_central(
            &config,
            &central_url,
            server_id.as_deref(),
            auth_header.as_deref(),
            &http_client,
        )
        .await
        {
            warn!("Failed to refresh config: {}", e);
            // On error, wait longer before next attempt
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}
