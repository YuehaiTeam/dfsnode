use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::auth::{AuthConfig, extract_sign_param};
use crate::metrics::MetricsGuard;

/// Configuration needed for WebTransport file download.
#[derive(Clone)]
pub struct WtConfig {
    /// Auth configuration (for signature verification).
    pub auth: AuthConfig,
    /// Root directory to serve files from.
    pub root: PathBuf,
    /// URL prefix to strip.
    pub prefix: String,
}

/// Handle a WebTransport session: verify signature → accept → open uni stream → push file → close.
pub async fn handle_webtransport(
    req: http::Request<()>,
    stream: h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    h3_conn: h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
    wt_config: &WtConfig,
) -> anyhow::Result<()> {
    let mut guard = MetricsGuard::new("wt");

    let uri_path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    // Strip URL prefix to get DAV-relative path
    // --- Signature verification (uses centralized auth logic) ---
    let sign_param = extract_sign_param(&query);
    let verified = wt_config.auth.verify_signature(&uri_path, sign_param.as_deref(), false);

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
    info!("WebTransport session established (id={session_id:?}) for: {uri_path}");

    // Resolve file path
    let file_path = wt_config.root.join(
        uri_path
            .strip_prefix('/')
            .unwrap_or(&uri_path),
    );

    if !file_path.exists() || !file_path.is_file() {
        warn!("WebTransport: file not found: {}", file_path.display());
        // Session is already accepted, just drop it to close
        drop(session);
        return Ok(());
    }

    // --- Open server→client unidirectional stream and push file ---
    let mut uni_stream = session.open_uni(session_id).await?;
    info!(
        "WebTransport: pushing file {} via uni stream",
        file_path.display()
    );

    let mut file = tokio::fs::File::open(&file_path).await?;
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
    info!("WebTransport: file sent ({} bytes), closing session", guard.bytes_sent_so_far());

    // Release the stream, then wait for the client to finish reading
    // before dropping session (which closes the QUIC connection).
    drop(uni_stream);
    let _ = session.accept_uni().await;
    Ok(())
}
