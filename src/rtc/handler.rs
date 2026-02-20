use std::path::PathBuf;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Shared state for the LOCK / WebRTC signaling handler.
#[derive(Clone)]
pub struct RtcState {
    /// Handle to the RtcManager for creating sessions.
    pub rtc_handle: super::RtcHandle,
    /// Root directory for file serving.
    pub root: PathBuf,
    /// URL prefix to strip from paths (e.g. "/dav").
    pub prefix: String,
}

/// A single ICE candidate as sent by the browser (`RTCIceCandidate`).
///
/// Only `candidate` is required; the rest are optional context that str0m
/// may use when adding remote candidates.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IceCandidate {
    /// The candidate attribute line (e.g. `"candidate:1 1 UDP 2130706431 …"`).
    pub candidate: String,
    /// SDP media stream identification tag (e.g. `"0"`).
    #[serde(default, rename = "sdpMid")]
    pub sdp_mid: Option<String>,
    /// Zero-based index of the m-line in the SDP.
    #[serde(default, rename = "sdpMLineIndex")]
    pub sdp_mline_index: Option<u16>,
}

/// Incoming SDP offer + ICE candidates from the client.
#[derive(serde::Deserialize)]
pub struct LockRequest {
    pub sdp: String,
    pub candidates: Vec<IceCandidate>,
}

/// SDP answer + server ICE candidates returned to the client.
#[derive(serde::Serialize)]
pub struct LockResponse {
    pub sdp: String,
    pub candidates: Vec<IceCandidate>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// LOCK handler — WebRTC DataChannel signaling endpoint.
///
/// Called from the router fallback after the method has already been verified
/// as LOCK.  Authentication is enforced by the auth middleware layer that
/// wraps the entire router.
///
/// `path` is the raw request URI path (prefix already stripped by the caller).
/// `uuid` is extracted from the request's `$` query parameter, if present.
pub async fn lock_handler(
    State(rtc_state): State<RtcState>,
    path: String,
    Json(lock_req): Json<LockRequest>,
    uuid: Option<String>,
) -> Response {
    debug!("LOCK handler hit: /{path}");

    if lock_req.sdp.is_empty() {
        warn!("LOCK: missing SDP");
        return error_response(StatusCode::BAD_REQUEST, "Missing sdp field".to_string());
    }

    // Resolve the file path on disk.
    let rel = path.trim_start_matches('/');
    let file_path = rtc_state.root.join(rel);

    match tokio::fs::metadata(&file_path).await {
        Ok(meta) if meta.is_file() => { /* ok */ }
        Ok(_) => {
            return error_response(StatusCode::NOT_FOUND, format!("Not a regular file: /{rel}"));
        }
        Err(_) => {
            return error_response(StatusCode::NOT_FOUND, format!("File not found: /{rel}"));
        }
    }

    // Create a WebRTC session.
    let uri_path = format!("/{path}");
    match rtc_state
        .rtc_handle
        .create_session(file_path, lock_req.sdp, lock_req.candidates, uuid, uri_path)
        .await
    {
        Ok((_session_id, sdp_answer, local_candidates)) => {
            debug!("LOCK: created RTC session for /{rel}");
            let resp = LockResponse {
                sdp: sdp_answer,
                candidates: local_candidates,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => {
            warn!("LOCK: RtcManager error: {e}");
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("WebRTC session setup failed: {e}"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn error_response(status: StatusCode, message: String) -> Response {
    let body = serde_json::json!({ "error": message });
    (status, Json(body)).into_response()
}
