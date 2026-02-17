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

    /// STUN server address for NAT traversal (e.g. "stun.l.google.com:19302").
    /// Only meaningful with --http3-port. When set, the HTTP/3 server will
    /// periodically send STUN Binding Requests to discover its public UDP
    /// address and keep the NAT mapping alive.
    #[arg(long)]
    pub stun_server: Option<String>,

    /// Interval in seconds between STUN keepalive requests (default: 20).
    #[arg(long)]
    pub stun_interval_secs: Option<u64>,

    /// Webhook URL to notify when public address changes (via STUN).
    /// Supports basic auth embedded in URL, e.g. "https://user:pass@example.com/hook".
    /// The public address (ip:port) is sent as POST body in plain text.
    #[arg(long)]
    pub webhook_url: Option<String>,
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
        if self.stun_server.is_some() && self.http3_port.is_none() {
            anyhow::bail!("--stun-server requires --http3-port to be specified");
        }

        // --stun-interval-secs must be positive
        if let Some(0) = self.stun_interval_secs {
            anyhow::bail!("--stun-interval-secs must be greater than 0");
        }

        Ok(())
    }
}
