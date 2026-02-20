use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec, Encoder, IntCounterVec, TextEncoder};
use serde::Deserialize;
use std::time::Duration;

lazy_static! {
    /// Total number of requests by protocol.
    /// Labels: protocol (http, h3, wt, rtc)
    pub static ref DFS_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "dfsnode_requests_total",
        "Total number of requests by protocol",
        &["protocol"]
    )
    .expect("failed to register dfsnode_requests_total");

    /// Total bytes sent by protocol.
    /// Labels: protocol (http, h3, wt, rtc)
    pub static ref DFS_BYTES_SENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "dfsnode_bytes_sent_total",
        "Total bytes sent by protocol",
        &["protocol"]
    )
    .expect("failed to register dfsnode_bytes_sent_total");
}

/// Gather and encode metrics in Prometheus text format.
pub fn gather_metrics() -> Vec<u8> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    buffer
}

/// Gather metrics in MinIO-compatible Prometheus text format.
///
/// Outputs `minio_bucket_api_traffic_sent_bytes` and `minio_bucket_api_total`
/// with labels matching MinIO v3 `/bucket/api/{bucket}` endpoint semantics.
/// All protocols are summed into a single bucket named "dfs".
pub fn gather_minio_compat_metrics() -> String {
    let protocols = &["http", "h3", "wt", "rtc"];

    let total_bytes: u64 = protocols
        .iter()
        .map(|p| DFS_BYTES_SENT_TOTAL.with_label_values(&[p]).get() as u64)
        .sum();

    let total_requests: u64 = protocols
        .iter()
        .map(|p| DFS_REQUESTS_TOTAL.with_label_values(&[p]).get() as u64)
        .sum();

    format!(
        "# HELP minio_bucket_api_traffic_received_bytes Total number of bytes sent\n\
         # TYPE minio_bucket_api_traffic_received_bytes counter\n\
         minio_bucket_api_traffic_received_bytes{{bucket=\"dfs\",type=\"s3\"}} {total_bytes}\n\
         # HELP minio_bucket_api_total Total number of requests\n\
         # TYPE minio_bucket_api_total counter\n\
         minio_bucket_api_total{{bucket=\"dfs\",name=\"GetObject\",type=\"s3\"}} {total_requests}\n"
    )
}

/// JWT claims expected from MinIO-compatible Prometheus scraper.
#[derive(Debug, Deserialize)]
struct MinioClaims {
    /// Must be "prometheus"
    iss: String,
    /// The access_key (username)
    #[allow(dead_code)]
    sub: String,
}

/// Validate a MinIO-compatible JWT token.
///
/// Expected format: HS256-signed, claims `{ sub: "<access_key>", iss: "prometheus" }`,
/// secret = the WebDAV password (MinIO's secret_key equivalent).
///
/// Returns `true` if the token is valid and `iss == "prometheus"`.
pub fn validate_minio_jwt(token: &str, secret: &str) -> bool {
    let mut validation = Validation::new(Algorithm::HS256);
    // MinIO tokens don't carry exp/aud by default; disable those checks
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_issuer(&["prometheus"]);

    let key = DecodingKey::from_secret(secret.as_bytes());
    match decode::<MinioClaims>(token, &key, &validation) {
        Ok(data) => data.claims.iss == "prometheus",
        Err(_) => false,
    }
}

/// Increment request counter for the given protocol.
pub fn record_request(protocol: &str) {
    DFS_REQUESTS_TOTAL.with_label_values(&[protocol]).inc();
}

/// Record bytes sent for the given protocol.
pub fn record_bytes_sent(protocol: &str, bytes: u64) {
    if bytes > 0 {
        DFS_BYTES_SENT_TOTAL
            .with_label_values(&[protocol])
            .inc_by(bytes);
    }
}

/// RAII guard that records request count and bytes sent on Drop.
///
/// Use this for protocols where the response body is not automatically polled
/// by hyper (WebTransport, WebRTC). The guard ensures metrics are recorded
/// even if the function exits early via `?`.
pub struct MetricsGuard {
    protocol: &'static str,
    bytes_sent: u64,
    recorded: bool,
    /// If true, only record bytes_sent on Drop (request count handled elsewhere).
    bytes_only: bool,
}

impl MetricsGuard {
    /// Create a guard that records both request count and bytes_sent on Drop.
    pub fn new(protocol: &'static str) -> Self {
        Self {
            protocol,
            bytes_sent: 0,
            recorded: false,
            bytes_only: false,
        }
    }

    /// Create a guard that only records bytes_sent on Drop (not request count).
    ///
    /// Use this when request counting is handled by another mechanism (e.g.
    /// MetricsBody via Tower Layer), but byte counting needs to be done
    /// separately (e.g. H3 where bytes are counted after successful send_data).
    pub fn new_bytes_only(protocol: &'static str) -> Self {
        Self {
            protocol,
            bytes_sent: 0,
            recorded: false,
            bytes_only: true,
        }
    }

    /// Add bytes to the running total (call after each successful send).
    pub fn add_bytes(&mut self, n: u64) {
        self.bytes_sent = self.bytes_sent.saturating_add(n);
    }

    /// Set the total bytes sent (call when the total is known at once).
    pub fn set_bytes(&mut self, n: u64) {
        self.bytes_sent = n;
    }

    /// Read current byte count (for logging).
    pub fn bytes_sent_so_far(&self) -> u64 {
        self.bytes_sent
    }

    /// Explicitly record now and prevent the Drop from recording again.
    pub fn record_now(&mut self) {
        if !self.recorded {
            if !self.bytes_only {
                record_request(self.protocol);
            }
            record_bytes_sent(self.protocol, self.bytes_sent);
            self.recorded = true;
        }
    }
}

impl Drop for MetricsGuard {
    fn drop(&mut self) {
        if !self.recorded {
            if !self.bytes_only {
                record_request(self.protocol);
            }
            record_bytes_sent(self.protocol, self.bytes_sent);
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics Push (remote-write to VictoriaMetrics / Prometheus)
// ---------------------------------------------------------------------------

/// A parsed push target with optional basic auth credentials.
struct PushTarget {
    /// URL without credentials (credentials stripped after parsing).
    url: String,
    /// Optional (username, password) extracted from the original URL.
    auth: Option<(String, String)>,
}

/// Parse a raw URL string, extract basic-auth credentials, and return a
/// [`PushTarget`] with a clean (credential-free) URL.
fn parse_push_url(raw: &str) -> Result<PushTarget, url::ParseError> {
    let parsed = url::Url::parse(raw)?;

    let auth = if !parsed.username().is_empty() {
        Some((
            parsed.username().to_string(),
            parsed.password().unwrap_or("").to_string(),
        ))
    } else {
        None
    };

    // Rebuild URL without embedded credentials
    let mut clean = parsed.clone();
    let _ = clean.set_username("");
    let _ = clean.set_password(None);

    Ok(PushTarget {
        url: clean.to_string(),
        auth,
    })
}

/// Spawn a background task that periodically pushes metrics to one or more
/// remote endpoints (e.g. VictoriaMetrics `/api/v1/import/prometheus`).
///
/// Each push sends **both** the standard Prometheus text format and the
/// MinIO-compatible format concatenated into a single body.
///
/// * `urls`     – raw push URLs (may contain basic-auth credentials).
/// * `interval` – time between consecutive pushes.
pub fn spawn_metrics_push(urls: Vec<String>, interval: Duration) {
    let targets: Vec<PushTarget> = urls
        .iter()
        .filter_map(|raw| match parse_push_url(raw) {
            Ok(t) => {
                tracing::info!(
                    "Metrics push target: {} (auth={})",
                    t.url,
                    t.auth.is_some()
                );
                Some(t)
            }
            Err(e) => {
                tracing::warn!("Invalid metrics push URL '{}': {}", raw, e);
                None
            }
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    // One shared client for all targets.
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to build metrics push HTTP client: {}", e);
            return;
        }
    };

    crate::panic_recovery::spawn_catch_panic("metrics-push", async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately — skip it so we don't push at
        // startup before any real data has been collected.
        ticker.tick().await;

        loop {
            ticker.tick().await;

            // Gather both formats and concatenate.
            let standard = gather_metrics();
            let minio = gather_minio_compat_metrics();
            let mut body = standard;
            body.extend_from_slice(minio.as_bytes());

            for target in &targets {
                let mut req = client
                    .post(&target.url)
                    .header("Content-Type", "text/plain; charset=utf-8")
                    .body(body.clone());

                if let Some((ref user, ref pass)) = target.auth {
                    req = req.basic_auth(user, Some(pass));
                }

                match req.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        tracing::debug!("Metrics pushed to {}", target.url);
                    }
                    Ok(resp) => {
                        tracing::warn!(
                            "Metrics push to {} returned {}",
                            target.url,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Metrics push to {} failed: {}", target.url, e);
                    }
                }
            }
        }
    });
}
