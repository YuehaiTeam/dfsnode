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

    /// Path to TLS certificate file (PEM format, required for HTTPS/HTTP3)
    #[arg(long)]
    pub cert: Option<String>,

    /// Path to TLS private key file (PEM format, required for HTTPS/HTTP3)
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
}

impl Args {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.http_port.is_none() && self.https_port.is_none() && self.http3_port.is_none() {
            anyhow::bail!(
                "At least one of --http-port, --https-port, or --http3-port must be specified"
            );
        }

        if (self.https_port.is_some() || self.http3_port.is_some())
            && (self.cert.is_none() || self.key.is_none())
        {
            anyhow::bail!(
                "--cert and --key are required when --https-port or --http3-port is specified"
            );
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

        Ok(())
    }
}
