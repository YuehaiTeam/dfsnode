use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use hyper_staticfile::Static;
use tokio::time::Duration as TokioDuration;

use crate::cache::FileSystemCache;
use crate::config::OptimizedConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ArcSwap<OptimizedConfig>>,
    pub data_dir: PathBuf,
    pub central_url: Option<String>,
    pub auth_header: Option<String>,
    pub server_id: Option<String>,
    pub static_service: Static,
    pub http_client: reqwest::Client,
    pub fs_cache: Arc<FileSystemCache>,
}

impl AppState {
    pub fn new(
        data_dir: PathBuf,
        central_url: Option<String>,
        auth_header: Option<String>,
        server_id: Option<String>,
    ) -> Self {
        let static_service = Static::new(&data_dir);

        // Configure HTTP client with optimized settings for better performance
        let http_client = reqwest::Client::builder()
            .pool_max_idle_per_host(50) // 增加连接池
            .pool_idle_timeout(TokioDuration::from_secs(300)) // 延长空闲时间
            .timeout(TokioDuration::from_secs(15)) // 减少超时时间
            .tcp_keepalive(TokioDuration::from_secs(600)) // 更长的 keepalive
            .tcp_nodelay(true) // Disable Nagle's algorithm for better latency
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config: Arc::new(ArcSwap::from_pointee(OptimizedConfig::default())),
            data_dir,
            central_url,
            auth_header,
            server_id,
            static_service,
            http_client,
            fs_cache: Arc::new(FileSystemCache::new()),
        }
    }
}

pub fn parse_central_url(
    central: &str,
) -> anyhow::Result<(Option<String>, Option<String>, Option<String>)> {
    use base64::Engine;
    use hyper::Uri;

    let uri: Uri = central.parse().context("Invalid central URL")?;

    let (auth_info, server_id) = uri
        .authority()
        .map(|auth| {
            let auth_str = auth.as_str();
            if let Some(at_pos) = auth_str.find('@') {
                let (userinfo, _host) = auth_str.split_at(at_pos);
                // Extract server_id from userinfo (before the colon)
                let server_id = userinfo.split(':').next().map(|s| s.to_string());
                (Some(userinfo), server_id)
            } else {
                (None, None)
            }
        })
        .unwrap_or((None, None));

    let auth_header = if let Some(userinfo) = auth_info {
        let encoded = base64::engine::general_purpose::STANDARD.encode(userinfo);
        Some(format!("Basic {}", encoded))
    } else {
        None
    };

    // Remove userinfo from URL
    let clean_url = if auth_info.is_some() {
        let scheme = uri.scheme_str().unwrap_or("https");
        let authority = uri.authority().unwrap().as_str();
        let host_port = authority.split('@').nth(1).unwrap_or(authority);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("");
        format!("{}://{}{}", scheme, host_port, path)
    } else {
        central.to_string()
    };

    Ok((Some(clean_url), auth_header, server_id))
}
