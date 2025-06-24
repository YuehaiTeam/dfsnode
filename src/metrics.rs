use prometheus::core::{AtomicU64, GenericCounter, GenericGauge};

// Global metrics
lazy_static::lazy_static! {
    pub static ref HTTP_REQUESTS_TOTAL: GenericCounter<AtomicU64> = GenericCounter::new(
        "dfs_requests_total", "Total number of HTTP requests"
    ).expect("Failed to create counter");

    pub static ref HTTP_BYTES_SENT_TOTAL: GenericCounter<AtomicU64> = GenericCounter::new(
        "dfs_bytes_sent_total", "Total bytes sent in HTTP responses"
    ).expect("Failed to create counter");

    pub static ref ACTIVE_CONNECTIONS: GenericGauge<AtomicU64> = GenericGauge::new(
        "dfs_active_connections", "Number of active connections"
    ).expect("Failed to create gauge");

    pub static ref CONFIG_VERSION: GenericGauge<AtomicU64> = GenericGauge::new(
        "dfs_config_version", "Current configuration version"
    ).expect("Failed to create gauge");
}

pub fn register_metrics() -> anyhow::Result<()> {
    prometheus::register(Box::new(HTTP_REQUESTS_TOTAL.clone()))?;
    prometheus::register(Box::new(HTTP_BYTES_SENT_TOTAL.clone()))?;
    prometheus::register(Box::new(ACTIVE_CONNECTIONS.clone()))?;
    prometheus::register(Box::new(CONFIG_VERSION.clone()))?;
    Ok(())
}
