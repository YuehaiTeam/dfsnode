use std::path::PathBuf;

use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::auth::{AuthConfig, extract_sign_param};

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
    let uri_path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    // Strip URL prefix to get DAV-relative path
    // --- Signature verification (uses centralized auth logic) ---
    let sign_param = extract_sign_param(&query);
    let verified = wt_config.auth.verify_signature(&uri_path, sign_param.as_deref());

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
    let bytes_sent = tokio::io::copy(&mut file, &mut uni_stream).await?;

    // Shutdown the stream to signal completion
    uni_stream.shutdown().await?;
    info!("WebTransport: file sent ({bytes_sent} bytes), closing session");

    // Drop session to close the connection
    drop(session);
    Ok(())
}
