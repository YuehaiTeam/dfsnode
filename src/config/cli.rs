use clap::Parser;

/// A WebDAV file server with OwnCloud checksum hash extension support.
///
/// Supports HTTP, HTTPS, and HTTP/3 (QUIC) protocols.
/// At least one of --http-port, --https-port, or --http3-port must be specified.
#[derive(Parser, Debug, Clone)]
#[command(name = "dfsnode", version, about)]
pub struct Args {
    /// Directory to serve via WebDAV
    #[arg(long, default_value = ".")]
    pub root: String,

    /// HTTP port (plain, unencrypted)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// HTTPS port (TLS over TCP)
    #[arg(long)]
    pub https_port: Option<u16>,

    /// HTTP/3 port (QUIC over UDP)
    #[arg(long)]
    pub http3_port: Option<u16>,

    /// Path to TLS certificate file (PEM format).
    /// If omitted when HTTPS/HTTP3 is enabled, a self-signed certificate is
    /// auto-generated and periodically renewed.
    #[arg(long)]
    pub cert: Option<String>,

    /// Path to TLS private key file (PEM format).
    /// Must be specified together with --cert.
    #[arg(long)]
    pub key: Option<String>,

    /// WebDAV URL prefix to strip
    #[arg(long, default_value = "/")]
    pub prefix: String,

    /// Username for HTTP Basic Authentication.
    /// When set together with --password, all requests require basic auth
    /// (except signed GET downloads).
    /// Mutually exclusive with --config.
    #[arg(long)]
    pub username: Option<String>,

    /// Password for HTTP Basic Authentication.
    /// Mutually exclusive with --config.
    #[arg(long)]
    pub password: Option<String>,

    /// HMAC secret token for signed GET downloads (hex string).
    /// When set, GET requests can bypass basic auth by providing a valid
    /// signature via the `$` query parameter.
    /// Mutually exclusive with --config.
    #[arg(long)]
    pub sign_key: Option<String>,

    /// Path to YAML configuration file.
    /// Mutually exclusive with --username, --password, --sign-key.
    #[arg(long)]
    pub config: Option<String>,

    /// STUN server address(es) for NAT traversal (e.g. "stun.l.google.com:19302").
    /// Can be specified multiple times. Only meaningful with --http3-port.
    /// When set, the HTTP/3 server will periodically send STUN Binding Requests
    /// to ALL resolved IPs to discover public UDP addresses and keep NAT mappings alive.
    #[arg(long, action = clap::ArgAction::Append)]
    pub stun_server: Vec<String>,

    /// Interval in seconds between STUN keepalive requests (default: 20).
    #[arg(long)]
    pub stun_interval_secs: Option<u64>,

    /// Webhook URL to notify when public address changes (via STUN).
    /// Supports basic auth embedded in URL, e.g. "https://user:pass@example.com/hook".
    /// The public address (ip:port) is sent as POST body in plain text.
    #[arg(long)]
    pub webhook_url: Option<String>,

    /// Enable WebRTC DataChannel file transfer via LOCK method signaling.
    /// Requires --http3-port with --stun-server for public address discovery.
    #[arg(long, default_value_t = false)]
    pub enable_rtc: bool,

    /// Disable file downloads via HTTP/1.1 and HTTP/2 GET requests.
    /// H3 and WebTransport downloads are not affected.
    /// Useful when WebRTC DataChannel is the preferred download method
    /// and TCP connections are only used for signaling (e.g. via frp tunnel).
    #[arg(long, default_value_t = false)]
    pub no_tcp_download: bool,

    /// Auto-generate TLS certificate when the existing one is untrusted
    /// by the system AND has less than 1 day of validity remaining.
    /// Requires --cert and --key to specify output paths.
    /// If the cert file does not exist, a new self-signed certificate is created.
    #[arg(long, default_value_t = false)]
    pub ssl_generate: bool,
}

impl Args {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.http_port.is_none() && self.https_port.is_none() && self.http3_port.is_none() {
            anyhow::bail!(
                "At least one of --http-port, --https-port, or --http3-port must be specified"
            );
        }

        // cert and key must both be set or both unset
        if self.cert.is_some() != self.key.is_some() {
            anyhow::bail!("--cert and --key must be specified together");
        }

        let root = std::path::Path::new(&self.root);
        if !root.exists() {
            anyhow::bail!("Root directory '{}' does not exist", self.root);
        }
        if !root.is_dir() {
            anyhow::bail!("Root path '{}' is not a directory", self.root);
        }

        // username and password must both be set or both unset
        if self.username.is_some() != self.password.is_some() {
            anyhow::bail!("--username and --password must be specified together");
        }

        // --config is mutually exclusive with --username, --password, --sign-key
        if self.config.is_some()
            && (self.username.is_some() || self.password.is_some() || self.sign_key.is_some())
        {
            anyhow::bail!(
                "--config is mutually exclusive with --username, --password, and --sign-key"
            );
        }

        // --stun-server requires --http3-port
        if !self.stun_server.is_empty() && self.http3_port.is_none() {
            anyhow::bail!("--stun-server requires --http3-port to be specified");
        }

        // --stun-interval-secs must be positive
        if let Some(0) = self.stun_interval_secs {
            anyhow::bail!("--stun-interval-secs must be greater than 0");
        }

        // --enable-rtc requires --http3-port and --stun-server
        if self.enable_rtc {
            if self.http3_port.is_none() {
                anyhow::bail!("--enable-rtc requires --http3-port to be specified");
            }
            if self.stun_server.is_empty() {
                anyhow::bail!("--enable-rtc requires --stun-server for public address discovery");
            }
        }

        // --no-tcp-download requires --enable-rtc or --http3-port (otherwise no download path remains)
        if self.no_tcp_download && self.http3_port.is_none() {
            anyhow::bail!("--no-tcp-download requires --http3-port (otherwise no download method is available)");
        }

        // --ssl-generate requires --cert and --key
        if self.ssl_generate && (self.cert.is_none() || self.key.is_none()) {
            anyhow::bail!("--ssl-generate requires --cert and --key to specify output paths");
        }

        Ok(())
    }
}
