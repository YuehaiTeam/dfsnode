use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use reqwest::Client;
use tracing::warn;
use url::Url;

use crate::auth::AuthConfig;
use crate::config::cli::RunArgs;
use crate::config::{ServiceConfig, load_config, parse_config_str};

pub const DEFAULT_CONFIG_REFRESH_SECS: u64 = 60;
pub const DEFAULT_CONFIG_GRACEFUL_PERIOD_SECS: u64 = 15 * 60;
pub const DEFAULT_METRICS_PUSH_INTERVAL_SECS: u64 = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsPushRuntimeConfig {
    pub urls: Vec<String>,
    pub interval: Duration,
}

impl Default for MetricsPushRuntimeConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            interval: Duration::from_secs(DEFAULT_METRICS_PUSH_INTERVAL_SECS),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LiveRuntimeConfig {
    pub revision: Option<String>,
    pub webhook_url: Option<String>,
    pub metrics_push: MetricsPushRuntimeConfig,
}

#[derive(Clone)]
pub struct LiveConfigHandle {
    inner: Arc<ArcSwap<LiveRuntimeConfig>>,
}

impl LiveConfigHandle {
    pub fn new(initial: LiveRuntimeConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(initial)),
        }
    }

    pub fn load_full(&self) -> Arc<LiveRuntimeConfig> {
        self.inner.load_full()
    }

    pub fn store(&self, next: LiveRuntimeConfig) {
        self.inner.store(Arc::new(next));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveStunConfig {
    pub servers: Vec<String>,
    pub interval_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct RemoteConfigFetcher {
    client: Client,
    url: String,
    auth: Option<(String, String)>,
}

impl RemoteConfigFetcher {
    fn new(raw_url: &str, ignore_invalid_certs: bool) -> anyhow::Result<Self> {
        let parsed = Url::parse(raw_url)
            .map_err(|e| anyhow::anyhow!("Invalid config URL: {e}"))?;

        let auth = if !parsed.username().is_empty() {
            Some((
                parsed.username().to_string(),
                parsed.password().unwrap_or("").to_string(),
            ))
        } else {
            None
        };

        let mut clean = parsed.clone();
        let _ = clean.set_username("");
        let _ = clean.set_password(None);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(ignore_invalid_certs)
            .build()
            .context("Failed to build remote config HTTP client")?;

        Ok(Self {
            client,
            url: clean.to_string(),
            auth,
        })
    }

    async fn fetch(&self) -> anyhow::Result<ServiceConfig> {
        let mut req = self.client.get(&self.url);
        if let Some((user, pass)) = &self.auth {
            req = req.basic_auth(user, Some(pass));
        }

        let resp = req.send().await.context("Failed to fetch remote config")?;
        let status = resp.status();
        let body = resp.text().await.context("Failed to read remote config body")?;

        if !status.is_success() {
            anyhow::bail!("Remote config fetch returned {status}: {body}");
        }

        parse_config_str(&body, &self.url)
    }
}

pub async fn load_service_config_source(args: &RunArgs) -> anyhow::Result<Option<ServiceConfig>> {
    if let Some(config_url) = &args.config_url {
        let fetcher = RemoteConfigFetcher::new(config_url, args.dangerous_ignore_ssl_certificate)?;
        return fetcher.fetch().await.map(Some);
    }

    if let Some(config_path) = &args.config {
        return load_config(Path::new(config_path)).map(Some);
    }

    Ok(None)
}

pub fn effective_stun_config(
    args: &RunArgs,
    service_config: Option<&ServiceConfig>,
) -> Option<EffectiveStunConfig> {
    let servers = if !args.stun_server.is_empty() {
        args.stun_server.clone()
    } else {
        service_config
            .and_then(|cfg| cfg.startup.stun.as_ref())
            .map(|stun| stun.all_servers())
            .unwrap_or_default()
    };

    if servers.is_empty() {
        return None;
    }

    let interval_secs = args.stun_interval_secs.or_else(|| {
        service_config
            .and_then(|cfg| cfg.startup.stun.as_ref())
            .and_then(|stun| stun.interval_secs)
    });

    Some(EffectiveStunConfig {
        servers,
        interval_secs,
    })
}

pub fn build_live_runtime_config(
    args: &RunArgs,
    service_config: Option<&ServiceConfig>,
) -> LiveRuntimeConfig {
    let mut push_urls = args.metrics_push_url.clone();
    let mut interval_secs = args.metrics_push_interval_secs;

    if let Some(metrics_push) = service_config.and_then(|cfg| cfg.live.metrics_push.as_ref()) {
        push_urls.extend(metrics_push.all_urls());
        if let Some(remote_interval) = metrics_push.interval_secs {
            interval_secs = Some(match interval_secs {
                Some(cli_interval) => cli_interval.min(remote_interval),
                None => remote_interval,
            });
        }
    }

    LiveRuntimeConfig {
        revision: service_config.and_then(|cfg| cfg.revision.clone()),
        webhook_url: args.webhook_url.clone().or_else(|| {
            service_config.and_then(|cfg| cfg.live.webhook_url.clone())
        }),
        metrics_push: MetricsPushRuntimeConfig {
            urls: push_urls,
            interval: Duration::from_secs(
                interval_secs.unwrap_or(DEFAULT_METRICS_PUSH_INTERVAL_SECS),
            ),
        },
    }
}

pub fn resolve_graceful_period(args: &RunArgs, service_config: Option<&ServiceConfig>) -> Duration {
    Duration::from_secs(
        service_config
            .and_then(|cfg| cfg.graceful_period)
            .or(args.config_graceful_period_secs)
            .unwrap_or(DEFAULT_CONFIG_GRACEFUL_PERIOD_SECS),
    )
}

pub fn resolve_refresh_delay(args: &RunArgs, service_config: Option<&ServiceConfig>) -> Duration {
    let fallback = Duration::from_secs(
        args.config_refresh_secs
            .unwrap_or(DEFAULT_CONFIG_REFRESH_SECS),
    );

    let Some(valid_until) = service_config.and_then(|cfg| cfg.valid_until) else {
        return fallback;
    };

    let now = time::OffsetDateTime::now_utc();
    let delta = valid_until - now;
    let millis = delta.whole_milliseconds();
    if millis <= 0 {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(millis as u64)
    }
}

pub fn spawn_remote_refresh_loop(
    args: RunArgs,
    auth: AuthConfig,
    live: LiveConfigHandle,
    initial_service_config: ServiceConfig,
    initial_stun: Option<EffectiveStunConfig>,
    restart_required: Arc<AtomicBool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let config_url = args
        .config_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("config_url missing for remote refresh loop"))?;
    let fetcher = RemoteConfigFetcher::new(config_url, args.dangerous_ignore_ssl_certificate)?;

    Ok(tokio::spawn(async move {
        let mut active_config = initial_service_config;
        let fallback_refresh = resolve_refresh_delay(&args, None);
        let mut next_delay = resolve_refresh_delay(&args, Some(&active_config));

        loop {
            tokio::time::sleep(next_delay).await;

            match fetcher.fetch().await {
                Ok(next_config) => {
                    let previous_grace = resolve_graceful_period(&args, Some(&active_config));
                    auth.apply_live_config(
                        &next_config.live.auth,
                        &args.prefix,
                        args.no_tcp_download,
                        Some(previous_grace),
                    );
                    live.store(build_live_runtime_config(&args, Some(&next_config)));

                    let next_stun = effective_stun_config(&args, Some(&next_config));
                    if next_stun != initial_stun
                        && !restart_required.swap(true, Ordering::SeqCst)
                    {
                        warn!(
                            "Remote startup config changed (STUN). Restart required before the new startup config can take effect."
                        );
                    }

                    active_config = next_config;
                    next_delay = resolve_refresh_delay(&args, Some(&active_config));
                }
                Err(err) => {
                    warn!("Failed to refresh remote config: {err}");
                    next_delay = fallback_refresh;
                }
            }
        }
    }))
}
