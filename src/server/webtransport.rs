use std::net::SocketAddr;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

use crate::auth::{AuthConfig, extract_sign_param};
use crate::metrics::MetricsGuard;
use crate::path_policy::PathPolicy;

/// Configuration needed for WebTransport file download.
#[derive(Clone)]
pub struct WtConfig {
    /// Auth configuration (for signature verification).
    pub auth: AuthConfig,
    /// Root directory to serve files from.
    pub root: PathBuf,
    /// URL prefix to strip.
    pub prefix: String,
    /// Shared filesystem path policy.
    pub path_policy: std::sync::Arc<PathPolicy>,
}

/// Handle a WebTransport session: verify signature → accept → open uni stream → push file → close.
pub async fn handle_webtransport(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    wt_config: &WtConfig,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut guard = MetricsGuard::new("wt");

    let uri_path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    // --- Signature verification (uses centralized auth logic) ---
    let sign_param = extract_sign_param(&query);
    let (verified, uuid) = wt_config.auth.verify_signature(&uri_path, sign_param.as_deref(), false);

    if !verified {
        warn!("WebTransport signature verification failed for: {uri_path}");
        // Reject: send 403 on the stream, do NOT accept the session
        let resp = http::Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(())
            .unwrap();
        let mut stream = stream;
        stream.send_response(resp).await?;
        stream.finish().await?;
        return Ok(());
    }

    // --- Accept WebTransport session ---
    let session =
        h3_webtransport::server::WebTransportSession::accept(req, stream, h3_conn).await?;
    let session_id = session.session_id();
    debug!("WebTransport session established (id={session_id:?}) for: {uri_path}");

    // --- Resolve file path (strip URL prefix, prevent directory traversal) ---
    let prefix = wt_config.prefix.trim_end_matches('/');
    let stripped = if !prefix.is_empty() && prefix != "/" {
        uri_path.strip_prefix(prefix).unwrap_or(&uri_path)
    } else {
        &uri_path
    };
    let rel = stripped.strip_prefix('/').unwrap_or(stripped);
    let file_path = wt_config.root.join(rel);

    let canonical_file = match wt_config.path_policy.resolve_existing(&file_path) {
        Ok(path) if path.is_file() => path,
        _ => {
            warn!(
                "WebTransport: file not accessible or outside allowed roots: {}",
                file_path.display()
            );
            drop(session);
            return Ok(());
        }
    };

    // --- Open server→client unidirectional stream and push file ---
    let mut uni_stream = session.open_uni(session_id).await?;
    debug!(
        "WebTransport: pushing file {} via uni stream",
        canonical_file.display()
    );

    let mut file = tokio::fs::File::open(&canonical_file).await?;
    let file_size = file.metadata().await?.len();

    // Send 8-byte big-endian file size header before file data
    uni_stream.write_all(&file_size.to_be_bytes()).await?;
    guard.add_bytes(8); // Count the 8-byte file size header

    // Stream file data in chunks, tracking bytes accurately even on error
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        uni_stream.write_all(&buf[..n]).await?;
        guard.add_bytes(n as u64);
    }

    // Shutdown the stream to signal completion (sends QUIC FIN)
    uni_stream.shutdown().await?;

    let bytes = guard.bytes_sent_so_far();
    let uuid_str = uuid.as_deref().unwrap_or("-");
    info!("[wt] {} {} {} {}", super::normalize_ip(peer_addr.ip()), uri_path, bytes, uuid_str);

    // Release the stream, then wait for the client to finish reading
    // before dropping session (which closes the QUIC connection).
    drop(uni_stream);
    let _ = session.accept_uni().await;
    Ok(())
}
