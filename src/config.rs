use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::Bytes;
use librqbit::dht::Id20;
use radix_trie::Trie;
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, interval};
use tracing::{info, warn};

use crate::app::AppState;
use crate::metrics::CONFIG_VERSION;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathConfig {
    pub autoindex: Option<bool>,
    pub signature: Option<String>,
    pub signature_expire_seconds: Option<u32>, // 签名过期时间，默认3600秒(1小时)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TorrentConfig {
    pub path: String,
    #[serde(with = "base64_serde")]
    pub torrent: Bytes,
    #[serde(default)]
    pub initial_peers: Vec<SocketAddr>,
}

mod base64_serde {
    use base64::{Engine as _, engine::general_purpose};
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let base64_string = general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&base64_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let base64_string = String::deserialize(deserializer)?;
        let vec = general_purpose::STANDARD.decode(&base64_string);
        vec.map(Bytes::from).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone)]
pub struct OptimizedConfig {
    pub version: u64,
    pub path_trie: Trie<String, PathConfig>,
    pub torrents: HashMap<Id20, TorrentConfig>,
    pub prometheus_auth_header: Option<String>, // 预计算的认证头
}

impl Default for OptimizedConfig {
    fn default() -> Self {
        Self {
            version: 0,
            path_trie: Trie::new(),
            torrents: HashMap::new(),
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

        // 将 TorrentConfig 数组转换为 HashMap<String, Vec<u8>>
        let mut torrents = HashMap::new();
        if let Some(torrent_configs) = &config.torrents {
            for torrent_config in torrent_configs {
                let torrent_info: Result<librqbit::TorrentMetaV1Borrowed> =
                    librqbit::torrent_from_bytes(&torrent_config.torrent);
                if let Ok(torrent_info) = torrent_info {
                    torrents.insert(torrent_info.info_hash, torrent_config.clone());
                } else {
                    warn!(
                        "Failed to parse torrent {}: {}",
                        torrent_config.path,
                        torrent_info.unwrap_err()
                    );
                }
            }
        }

        // 预计算 Prometheus 认证头
        let prometheus_auth_header = config
            .management_token
            .as_ref()
            .map(|token| format!("Bearer {}", token));

        Self {
            version: config.version.unwrap_or(0),
            path_trie,
            torrents,
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
    pub torrents: Option<Vec<TorrentConfig>>, // torrent配置数组
    pub management_token: Option<String>,
}

pub async fn load_config_from_file(
    config: &Arc<ArcSwap<OptimizedConfig>>,
    config_path: &str,
    state: &AppState,
) -> Result<()> {
    let content = tokio::fs::read_to_string(config_path).await?;
    let config_data: Config = serde_yml::from_str(&content)?;
    let optimized_config = OptimizedConfig::from_config(config_data.clone());
    let new_torrents = optimized_config.torrents.clone();
    let version = config_data.version.unwrap_or(0);

    config.store(Arc::new(optimized_config));

    // 更新配置版本指标
    CONFIG_VERSION.set(version);

    let state_cl = state.clone();
    tokio::spawn(async move {
        if let Err(e) = sync_torrents(&state_cl.bt_api, &new_torrents, &state_cl.data_dir).await {
            warn!("Failed to sync torrents: {}", e);
        }
    });

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
    state: &AppState,
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
    let current_version = config.load().get_version(); // 仅在版本号更新时才解析并替换配置
    if new_version != current_version {
        let optimized_config = OptimizedConfig::from_config(config_data);
        let new_torrents = optimized_config.torrents.clone();

        config.store(Arc::new(optimized_config));

        // 更新配置版本指标
        CONFIG_VERSION.set(new_version);

        // 新建一个task来同步torrents
        let state_cl = state.clone();
        tokio::spawn(async move {
            if let Err(e) = sync_torrents(&state_cl.bt_api, &new_torrents, &state_cl.data_dir).await
            {
                warn!("Failed to sync torrents: {}", e);
            }
        });

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
    state: &AppState,
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
            state,
        )
        .await
        {
            warn!("Failed to refresh config: {}", e);
            // On error, wait longer before next attempt
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

// Torrent管理功能
pub async fn sync_torrents(
    bt_api: &librqbit::Api,
    torrents: &HashMap<Id20, TorrentConfig>,
    data_dir: &std::path::Path,
) -> Result<()> {
    let data_dir_abs =
        std::path::absolute(data_dir).context("Failed to get absolute data directory path")?;
    let pre_torrents = bt_api.api_torrent_list();
    for (info_hash, torrent) in torrents {
        // 检查是否已存在相同info_hash的torrent
        if pre_torrents
            .torrents
            .iter()
            .any(|t| t.info_hash == info_hash.as_string())
        {
            info!("Torrent {} already exists, skipping", torrent.path);
            continue;
        }
        let path_with_dot = if torrent.path.starts_with('/') {
            format!(".{}", torrent.path)
        } else {
            torrent.path.to_string()
        };
        let torrent_path = data_dir_abs.join(path_with_dot);
        let torrent_path_str = std::path::absolute(torrent_path)?
            .to_string_lossy()
            .to_string();
        info!("Adding torrent {}", torrent_path_str);
        let res = bt_api
            .api_add_torrent(
                librqbit::AddTorrent::TorrentFileBytes(torrent.torrent.clone()),
                Some(librqbit::AddTorrentOptions {
                    output_folder: Some(torrent_path_str),
                    sub_folder: None,
                    overwrite: true,
                    initial_peers: Some(torrent.initial_peers.clone()),
                    ..Default::default()
                }),
            )
            .await;
        if let Err(e) = res {
            warn!("Failed to add torrent {}: {}", torrent.path, e);
        } else {
            info!(
                "Added torrent {}: {:?}",
                torrent.path,
                serde_json::to_string(&res)
            );
        }
    }
    // 删除不存在的torrent
    for pre_torrent in &pre_torrents.torrents {
        let id20 = Id20::from_str(&pre_torrent.info_hash);
        if let Ok(id20) = id20 {
            if !torrents.contains_key(&id20) {
                info!("Removing torrent {}", pre_torrent.info_hash);
                if let Err(e) = bt_api
                    .api_torrent_action_delete(librqbit::api::TorrentIdOrHash::Hash(id20))
                    .await
                {
                    warn!("Failed to remove torrent {}: {}", pre_torrent.info_hash, e);
                } else {
                    info!("Removed torrent {}", pre_torrent.info_hash);
                }
            }
        }
    }
    Ok(())
}
