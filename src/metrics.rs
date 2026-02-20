use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec, Encoder, IntCounterVec, TextEncoder};
use serde::Deserialize;

lazy_static! {
    /// Total number of requests by protocol.
    /// Labels: protocol (http, h3, wt, rtc)
    pub static ref DFS_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        "dfs_requests_total",
        "Total number of requests by protocol",
        &["protocol"]
    )
    .expect("failed to register dfs_requests_total");

    /// Total bytes sent by protocol.
    /// Labels: protocol (http, h3, wt, rtc)
    pub static ref DFS_BYTES_SENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "dfs_bytes_sent_total",
        "Total bytes sent by protocol",
        &["protocol"]
    )
    .expect("failed to register dfs_bytes_sent_total");
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
