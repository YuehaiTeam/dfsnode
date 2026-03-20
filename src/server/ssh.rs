use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use russh::server::{Auth, Msg, Server, Session};
use russh::{Channel, ChannelId};
use tower::Service;
use tracing::{debug, info, warn};
use crate::auth::AuthConfig;
use crate::path_policy::PathPolicy;

use super::sftp::{SftpAccess, SftpHandler};

/// Start an SSH server that serves HTTP/1.1 over direct-tcpip port-forwarded channels
/// and SFTP over session channels.
pub async fn serve(
    port: u16,
    host_key_path: &Path,
    app: Router,
    auth: AuthConfig,
    root: PathBuf,
    prefix: String,
    path_policy: Arc<PathPolicy>,
) -> anyhow::Result<()> {
    let host_key = if host_key_path.exists() {
        russh::keys::load_secret_key(host_key_path, None)
            .map_err(|e| anyhow::anyhow!("Failed to load SSH host key '{}': {e}", host_key_path.display()))?
    } else {
        info!("SSH host key not found at '{}', generating Ed25519 key...", host_key_path.display());
        let key = russh::keys::PrivateKey::random(&mut russh::keys::ssh_key::rand_core::OsRng, russh::keys::Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Failed to generate SSH host key: {e}"))?;
        if let Some(parent) = host_key_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let pem = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("Failed to encode SSH host key: {e}"))?;
        std::fs::write(host_key_path, pem.as_str())
            .map_err(|e| anyhow::anyhow!("Failed to write SSH host key to '{}': {e}", host_key_path.display()))?;
        let fingerprint = key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
        info!("SSH host key generated:\n  Fingerprint: {fingerprint}\n  Saved to: {}", host_key_path.display());
        key
    };

    let mut method = russh::MethodSet::empty();
    method.push(russh::MethodKind::Password);
    method.push(russh::MethodKind::None);

    let config = russh::server::Config {
        keys: vec![host_key],
        inactivity_timeout: Some(Duration::from_secs(600)),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        methods: method,
        server_id: russh::SshId::Standard("SSH-2.0-acme".to_string()),
        ..Default::default()
    };

    let addr = format!("[::]:{port}");
    info!("SSH server listening on ssh://{addr}");

    let listener = super::bind_dual_stack_tcp(port)?;
    let mut server = SshServer {
        app,
        auth,
        root,
        prefix,
        path_policy,
    };
    server
        .run_on_socket(Arc::new(config), &listener)
        .await
        .map_err(|e| anyhow::anyhow!("SSH server error: {e}"))?;

    Ok(())
}

/// SSH server that creates a new [`SshHandler`] for each incoming connection.
#[derive(Clone)]
struct SshServer {
    app: Router,
    auth: AuthConfig,
    root: PathBuf,
    prefix: String,
    path_policy: Arc<PathPolicy>,
}

impl russh::server::Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> SshHandler {
        debug!("SSH connection from {peer_addr:?}");
        SshHandler {
            peer_addr,
            app: self.app.clone(),
            auth: self.auth.clone(),
            root: self.root.clone(),
            prefix: self.prefix.clone(),
            path_policy: self.path_policy.clone(),
            auth_mode: AuthMode::None,
            channels: HashMap::new(),
        }
    }
}

/// Authentication mode determined during SSH password auth.
#[derive(Clone, Debug)]
pub(crate) enum AuthMode {
    /// No auth configured or not yet authenticated.
    None,
    /// Authenticated via WebDAV basic credentials — full read-only access.
    WebDav,
    /// Authenticated via path/signature — single file read-only access.
    /// Contains the normalized path (with prefix, e.g., "/dav/foo.txt")
    /// and the UUID from the signature (first 32 hex chars), if present.
    Signature { path: String, uuid: Option<String> },
}

/// Per-connection SSH handler.
struct SshHandler {
    peer_addr: Option<SocketAddr>,
    app: Router,
    auth: AuthConfig,
    root: PathBuf,
    prefix: String,
    path_policy: Arc<PathPolicy>,
    auth_mode: AuthMode,
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    /// Accept "none" authentication only when no auth is configured at all.
    fn auth_none(
        &mut self,
        _user: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        let accept = !self.auth.has_any_auth();
        if accept {
            self.auth_mode = AuthMode::None;
        }
        async move {
            if accept {
                Ok(Auth::Accept)
            } else {
                Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
            }
        }
    }

    /// Password authentication with two modes:
    /// 1. WebDAV credentials: user/pass match the configured basic-auth
    /// 2. Signature: user is a file path, pass is the sign value (range check skipped)
    ///
    /// When no auth is configured (no basic-auth, no sign key), any user/pass is accepted.
    ///
    /// Username normalization:
    /// - If starts with "2f" (hex '/'), hex-decode the entire username as the path
    /// - Otherwise, ensure it starts with '/'
    fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        let no_auth = !self.auth.has_any_auth();

        // Normalize username for signature verification (path normalization)
        let path = normalize_ssh_username(user);

        // Mode 1: WebDAV basic-auth credentials
        let basic_ok = self.auth.matches_basic_credentials(user, password);

        // Mode 2: Signature — normalized username is a file path, password is the sign value
        let (sign_ok, sign_uuid) = if !basic_ok {
            tracing::debug!("SSH auth attempt with signature credentials: user='{user}' (normalized path: '{path}')");
            self.auth.verify_signature(&path, Some(password), true)
        } else {
            (false, None)
        };

        // Record which auth mode succeeded for SFTP access control
        if no_auth || basic_ok {
            self.auth_mode = AuthMode::WebDav;
        } else if sign_ok {
            self.auth_mode = AuthMode::Signature { path: path.clone(), uuid: sign_uuid };
        }

        let peer = self.peer_addr;

        async move {
            if no_auth || basic_ok || sign_ok {
                debug!("SSH auth accepted for '{user}' from {peer:?}");
                Ok(Auth::Accept)
            } else {
                debug!("SSH auth rejected for '{user}' from {peer:?}");
                Ok(Auth::Reject { proceed_with_methods: None, partial_success: false })
            }
        }
    }

    /// Reject public-key authentication — only password is supported.
    fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<Auth, Self::Error>> + Send {
        async { Ok(Auth::Reject { proceed_with_methods: None, partial_success: false }) }
    }

    /// Accept session channels and store them for later subsystem requests (SFTP).
    fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let id = channel.id();
        self.channels.insert(id, channel);
        debug!("SSH session channel {id} opened from {:?}", self.peer_addr);
        async { Ok(true) }
    }

    /// Handle subsystem requests — only "sftp" is supported.
    fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send {
        if name == "sftp" {
            if let Some(channel) = self.channels.remove(&channel_id) {
                session.channel_success(channel_id).ok();
                let access = match &self.auth_mode {
                    AuthMode::None | AuthMode::WebDav => {
                        SftpAccess::full(
                            self.root.clone(),
                            self.prefix.clone(),
                            self.path_policy.clone(),
                        )
                    }
                    AuthMode::Signature { path, .. } => {
                        SftpAccess::single_file(
                            self.root.clone(),
                            self.prefix.clone(),
                            path.clone(),
                            self.path_policy.clone(),
                        )
                    }
                };
                let peer = self.peer_addr;
                let uuid = match &self.auth_mode {
                    AuthMode::Signature { uuid, .. } => uuid.clone(),
                    _ => None,
                };
                debug!("SFTP subsystem started for {peer:?} (mode: {:?})", self.auth_mode);
                crate::panic_recovery::spawn_catch_panic("sftp-session", async move {
                    let handler = SftpHandler::new(access, peer, uuid);
                    russh_sftp::server::run(channel.into_stream(), handler).await;
                    debug!("SFTP session ended for {peer:?}");
                });
            } else {
                warn!("SFTP subsystem requested on unknown channel {channel_id} from {:?}", self.peer_addr);
                session.channel_failure(channel_id).ok();
            }
        } else {
            debug!("Unknown subsystem '{name}' rejected from {:?}", self.peer_addr);
            session.channel_failure(channel_id).ok();
        }
        async { Ok(()) }
    }

    /// Reject remote port forwarding (tcpip-forward) — only direct-tcpip is supported.
    fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        warn!("SSH tcpip-forward rejected from {:?}", self.peer_addr);
        async { Ok(false) }
    }

    /// Accept ALL direct-tcpip channel requests (regardless of destination host/port)
    /// and bridge each one to the internal HTTP service.
    ///
    /// The requested `host_to_connect` and `port_to_connect` are logged but ignored —
    /// all channels are served by the same embedded HTTP router.
    fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        _session: &mut Session,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let peer_addr = self.peer_addr;
        let app = self.app.clone();
        let host = host_to_connect.to_string();

        async move {
            debug!(
                "SSH direct-tcpip from {peer_addr:?} \
                 (originator {originator_address}:{originator_port}) \
                 -> {host}:{port_to_connect} (virtual HTTP bridge)"
            );

            // Spawn a task to serve HTTP over this channel.
            // The channel is accepted (Ok(true)) and the HTTP bridge runs
            // independently of the SSH session handler.
            crate::panic_recovery::spawn_catch_panic("ssh-direct-tcpip", async move {
                let stream = channel.into_stream();
                let io = hyper_util::rt::TokioIo::new(stream);
                let service =
                    hyper::service::service_fn(
                        move |mut req: hyper::Request<hyper::body::Incoming>| {
                            let mut app = app.clone();
                            let addr = peer_addr;
                            async move {
                                if let Some(addr) = addr {
                                    req.extensions_mut()
                                        .insert(axum::extract::ConnectInfo(addr));
                                }
                                let resp =
                                    app.call(req).await.unwrap_or_else(|err| match err {});
                                Ok::<_, std::convert::Infallible>(resp)
                            }
                        },
                    );

                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await
                {
                    debug!("SSH HTTP connection error from {peer_addr:?}: {e}");
                }
            });

            Ok(true)
        }
    }
}

/// Normalize SSH username for use as a file path.
///
/// - If the first two characters are "2f" (hex for '/'), hex-decode the entire username.
/// - Otherwise, ensure it starts with '/'.
fn normalize_ssh_username(user: &str) -> String {
    let name = if user.len() >= 2 && user.as_bytes()[..2].eq_ignore_ascii_case(b"2f") {
        hex::decode(user)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| user.to_string())
    } else {
        user.to_string()
    };
    if name.starts_with('/') {
        name
    } else {
        format!("/{name}")
    }
}
