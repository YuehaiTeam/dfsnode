use std::ffi::OsString;

use clap::{ArgAction, Args as ClapArgs, Parser, Subcommand};

/// A WebDAV file server with OwnCloud checksum hash extension support.
///
/// Supports HTTP, HTTPS, HTTP/3 (QUIC), and HTTP-over-SSH protocols.
/// At least one of --http-port, --https-port, --http3-port, or --ssh-port must be specified.
#[derive(Parser, Debug, Clone)]
#[command(name = "dfsnode", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    #[command(name = "windows-service")]
    WindowsService(WindowsServiceArgs),
}

#[derive(ClapArgs, Debug, Clone)]
pub struct WindowsServiceArgs {
    /// Install Windows service with the given service name.
    #[arg(long)]
    pub install: Option<String>,

    /// Uninstall Windows service with the given service name.
    #[arg(long)]
    pub uninstall: Option<String>,

    /// Internal: run as service supervisor process.
    #[arg(long, hide = true, default_value_t = false)]
    pub service_supervisor: bool,

    /// Internal: run as service child process.
    #[arg(long, hide = true, default_value_t = false)]
    pub service_child: bool,

    /// Internal: service name for supervisor runtime.
    #[arg(long, hide = true)]
    pub service_name: Option<String>,

    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(ClapArgs, Debug, Clone)]
pub struct RunArgs {
    /// Directory to serve via WebDAV
    #[arg(long, default_value = ".")]
    pub root: String,

    /// Allow symlink/junction targets under this real directory tree.
    /// Can be specified multiple times.
    #[arg(long, action = ArgAction::Append)]
    pub allow_link_target: Vec<String>,

    /// HTTP port (plain, unencrypted)
    #[arg(long)]
    pub http_port: Option<u16>,

    /// HTTPS port (TLS over TCP)
    #[arg(long)]
    pub https_port: Option<u16>,

    /// HTTP/3 port (QUIC over UDP)
    #[arg(long)]
    pub http3_port: Option<u16>,

    /// SSH port (HTTP-over-SSH via direct-tcpip port forwarding)
    #[arg(long)]
    pub ssh_port: Option<u16>,

    /// Path to SSH server host key (PEM format, e.g. ed25519 or RSA).
    /// Required when --ssh-port is specified.
    #[arg(long)]
    pub ssh_host_key: Option<String>,

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
    /// Mutually exclusive with --config and --config-url.
    #[arg(long)]
    pub sign_key: Option<String>,

    /// Path to a YAML service configuration file, loaded once at startup.
    /// Mutually exclusive with --config-url, --username, --password, --sign-key.
    #[arg(long)]
    pub config: Option<String>,

    /// URL of a YAML service configuration file.
    /// When set, the client periodically refreshes the config from this URL.
    /// Supports basic auth embedded in the URL.
    /// Mutually exclusive with --config, --username, --password, --sign-key.
    #[arg(long)]
    pub config_url: Option<String>,

    /// Default config refresh interval in seconds when the service config omits valid_until.
    #[arg(long)]
    pub config_refresh_secs: Option<u64>,

    /// Default graceful period in seconds when the service config omits graceful_period.
    #[arg(long)]
    pub config_graceful_period_secs: Option<u64>,

    /// Dangerously disable TLS certificate validation for remote config,
    /// webhook, and metrics push HTTP clients. Intended for local debugging only.
    #[arg(long, default_value_t = false)]
    pub dangerous_ignore_ssl_certificate: bool,

    /// STUN server address(es) for NAT traversal (e.g. "stun.l.google.com:19302").
    /// Can be specified multiple times. Only meaningful with --http3-port.
    /// When set, the HTTP/3 server will periodically send STUN Binding Requests
    /// to ALL resolved IPs to discover public UDP addresses and keep NAT mappings alive.
    #[arg(long, action = ArgAction::Append)]
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

    /// Enable TUS resumable uploads.
    /// If omitted, TUS is disabled unless another --tus-* flag is provided.
    #[arg(long, default_value_t = false)]
    pub enable_tus: bool,

    /// Temporary directory for TUS upload session files.
    #[arg(long)]
    pub tus_temp_dir: Option<String>,

    /// Expiration timeout for inactive TUS uploads, in hours.
    #[arg(long)]
    pub tus_upload_timeout_hours: Option<u64>,

    /// Maximum number of concurrent TUS uploads.
    #[arg(long)]
    pub tus_max_concurrent_uploads: Option<usize>,

    /// Maximum upload size for a single TUS file, in bytes.
    #[arg(long)]
    pub tus_max_upload_size: Option<u64>,

    /// Trust reverse-proxy headers for client IP extraction.
    /// Accepted values: XRealIp, RightmostXForwardedFor, CfConnectingIp,
    /// TrueClientIp, FlyClientIp, RightmostForwarded.
    /// When omitted, the socket peer address is used directly.
    #[arg(long)]
    pub real_ip: Option<String>,

    /// Auto-generate TLS certificate when the existing one is untrusted
    /// by the system AND has less than 1 day of validity remaining.
    /// Requires --cert and --key to specify output paths.
    /// If the cert file does not exist, a new self-signed certificate is created.
    #[arg(long, default_value_t = false)]
    pub ssl_generate: bool,

    /// URL to push metrics to (e.g. "http://user:pass@victoriametrics:8428/api/v1/import/prometheus").
    /// Supports basic auth embedded in URL. Can be specified multiple times.
    /// If also set in config file, all URLs receive pushes.
    #[arg(long, action = ArgAction::Append)]
    pub metrics_push_url: Vec<String>,

    /// Interval in seconds between metrics pushes (default: 15).
    /// If also set in config file, the smaller value is used.
    #[arg(long)]
    pub metrics_push_interval_secs: Option<u64>,
}

impl Cli {
    pub fn validate(&self) -> anyhow::Result<()> {
        match &self.command {
            Some(Command::WindowsService(cmd)) => cmd.validate(),
            None => self.run.validate(),
        }
    }
}

impl WindowsServiceArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        let mode_count = self.install.is_some() as u8
            + self.uninstall.is_some() as u8
            + self.service_supervisor as u8
            + self.service_child as u8;

        if mode_count != 1 {
            anyhow::bail!(
                "windows-service requires exactly one mode: --install, --uninstall, --service-supervisor, or --service-child"
            );
        }

        if let Some(name) = &self.install {
            validate_service_name(name)?;
            self.run.validate()?;
        }

        if let Some(name) = &self.uninstall {
            validate_service_name(name)?;
        }

        if self.service_supervisor {
            let name = self
                .service_name
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--service-supervisor requires --service-name"))?;
            validate_service_name(name)?;
            self.run.validate()?;
        }

        if self.service_child {
            self.run.validate()?;
        }

        Ok(())
    }
}

impl RunArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.http_port.is_none()
            && self.https_port.is_none()
            && self.http3_port.is_none()
            && self.ssh_port.is_none()
        {
            anyhow::bail!(
                "At least one of --http-port, --https-port, --http3-port, or --ssh-port must be specified"
            );
        }

        // --ssh-port requires --ssh-host-key
        if self.ssh_port.is_some() && self.ssh_host_key.is_none() {
            anyhow::bail!("--ssh-port requires --ssh-host-key to be specified");
        }

        // Validate SSH host key path is not a directory (file will be auto-generated if missing)
        if let Some(ref path) = self.ssh_host_key {
            let p = std::path::Path::new(path);
            if p.exists() && !p.is_file() {
                anyhow::bail!("SSH host key path '{}' is not a file", path);
            }
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

        for target in &self.allow_link_target {
            let path = std::path::Path::new(target);
            if !path.exists() {
                anyhow::bail!("Allow link target '{}' does not exist", target);
            }
            if !path.is_dir() {
                anyhow::bail!("Allow link target '{}' is not a directory", target);
            }
            let _ = path.canonicalize().map_err(|e| {
                anyhow::anyhow!("Failed to canonicalize allow link target '{}': {e}", target)
            })?;
        }

        // username and password must both be set or both unset
        if self.username.is_some() != self.password.is_some() {
            anyhow::bail!("--username and --password must be specified together");
        }

        // --config is mutually exclusive with --username, --password, --sign-key
        if self.config.is_some() && self.config_url.is_some() {
            anyhow::bail!("--config and --config-url are mutually exclusive");
        }

        if (self.config.is_some() || self.config_url.is_some())
            && (self.username.is_some() || self.password.is_some() || self.sign_key.is_some())
        {
            anyhow::bail!(
                "--config/--config-url are mutually exclusive with --username, --password, and --sign-key"
            );
        }

        if let Some(0) = self.config_refresh_secs {
            anyhow::bail!("--config-refresh-secs must be greater than 0");
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
            if self.stun_server.is_empty() && self.config.is_none() && self.config_url.is_none() {
                anyhow::bail!(
                    "--enable-rtc requires either --stun-server or a service config source for public address discovery"
                );
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

        if let Some(0) = self.tus_upload_timeout_hours {
            anyhow::bail!("--tus-upload-timeout-hours must be greater than 0");
        }

        if let Some(0) = self.tus_max_concurrent_uploads {
            anyhow::bail!("--tus-max-concurrent-uploads must be greater than 0");
        }

        if let Some(0) = self.tus_max_upload_size {
            anyhow::bail!("--tus-max-upload-size must be greater than 0");
        }

        Ok(())
    }

    pub fn to_cli_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();

        push_kv(&mut args, "--root", &self.root);
        for target in &self.allow_link_target {
            push_kv(&mut args, "--allow-link-target", target);
        }

        push_opt_u16(&mut args, "--http-port", self.http_port);
        push_opt_u16(&mut args, "--https-port", self.https_port);
        push_opt_u16(&mut args, "--http3-port", self.http3_port);
        push_opt_u16(&mut args, "--ssh-port", self.ssh_port);
        push_opt_str(&mut args, "--ssh-host-key", self.ssh_host_key.as_deref());
        push_opt_str(&mut args, "--cert", self.cert.as_deref());
        push_opt_str(&mut args, "--key", self.key.as_deref());
        push_kv(&mut args, "--prefix", &self.prefix);
        push_opt_str(&mut args, "--username", self.username.as_deref());
        push_opt_str(&mut args, "--password", self.password.as_deref());
        push_opt_str(&mut args, "--sign-key", self.sign_key.as_deref());
        push_opt_str(&mut args, "--config", self.config.as_deref());
        push_opt_str(&mut args, "--config-url", self.config_url.as_deref());
        push_opt_u64(&mut args, "--config-refresh-secs", self.config_refresh_secs);
        push_opt_u64(
            &mut args,
            "--config-graceful-period-secs",
            self.config_graceful_period_secs,
        );
        if self.dangerous_ignore_ssl_certificate {
            args.push(OsString::from("--dangerous-ignore-ssl-certificate"));
        }

        for server in &self.stun_server {
            push_kv(&mut args, "--stun-server", server);
        }
        push_opt_u64(&mut args, "--stun-interval-secs", self.stun_interval_secs);
        push_opt_str(&mut args, "--webhook-url", self.webhook_url.as_deref());

        if self.enable_rtc {
            args.push(OsString::from("--enable-rtc"));
        }
        if self.no_tcp_download {
            args.push(OsString::from("--no-tcp-download"));
        }
        if self.enable_tus {
            args.push(OsString::from("--enable-tus"));
        }
        push_opt_str(&mut args, "--tus-temp-dir", self.tus_temp_dir.as_deref());
        push_opt_u64(
            &mut args,
            "--tus-upload-timeout-hours",
            self.tus_upload_timeout_hours,
        );
        if let Some(value) = self.tus_max_concurrent_uploads {
            push_kv(
                &mut args,
                "--tus-max-concurrent-uploads",
                &value.to_string(),
            );
        }
        push_opt_u64(&mut args, "--tus-max-upload-size", self.tus_max_upload_size);

        push_opt_str(&mut args, "--real-ip", self.real_ip.as_deref());
        if self.ssl_generate {
            args.push(OsString::from("--ssl-generate"));
        }

        for url in &self.metrics_push_url {
            push_kv(&mut args, "--metrics-push-url", url);
        }
        push_opt_u64(
            &mut args,
            "--metrics-push-interval-secs",
            self.metrics_push_interval_secs,
        );

        args
    }
}

fn validate_service_name(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("Service name must not be empty");
    }
    if name.contains('/') || name.contains('\\') {
        anyhow::bail!("Service name must not contain path separators");
    }
    Ok(())
}

fn push_kv(args: &mut Vec<OsString>, key: &str, value: &str) {
    args.push(OsString::from(key));
    args.push(OsString::from(value));
}

fn push_opt_str(args: &mut Vec<OsString>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        push_kv(args, key, value);
    }
}

fn push_opt_u16(args: &mut Vec<OsString>, key: &str, value: Option<u16>) {
    if let Some(value) = value {
        push_kv(args, key, &value.to_string());
    }
}

fn push_opt_u64(args: &mut Vec<OsString>, key: &str, value: Option<u64>) {
    if let Some(value) = value {
        push_kv(args, key, &value.to_string());
    }
}
