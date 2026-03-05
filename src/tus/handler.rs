use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{head, options};
use axum::Router;
use tracing::{debug, info, warn};

use crate::path_policy::PathPolicyError;
use crate::tus::{TusUploadManager, decode_tus_metadata};

/// Shared state for TUS handlers.
#[derive(Clone)]
pub struct TusState {
    pub manager: Arc<TusUploadManager>,
    pub root: PathBuf,
    pub prefix: String,
    pub path_policy: Arc<crate::path_policy::PathPolicy>,
}

/// Build axum routes for TUS resumable uploads.
///
/// All routes are mounted under `{prefix}/.tus-uploads`.
pub fn tus_routes(
    prefix: &str,
    manager: Arc<TusUploadManager>,
    root: PathBuf,
    path_policy: Arc<crate::path_policy::PathPolicy>,
) -> Router {
    let prefix_clean = prefix.trim_end_matches('/').to_string();
    let tus_base = format!("{}/.tus-uploads", prefix_clean);

    let state = TusState {
        manager,
        root,
        prefix: prefix_clean,
        path_policy,
    };

    Router::new()
        // OPTIONS on the collection endpoint
        .route(
            &tus_base,
            options(tus_options).post(tus_create),
        )
        .route(
            &format!("{}/", tus_base),
            options(tus_options).post(tus_create),
        )
        // Per-session routes
        .route(
            &format!("{}/{{session_id}}", tus_base),
            head(tus_head)
                .patch(tus_patch)
                .delete(tus_delete)
                .options(tus_options),
        )
        .with_state(state)
}

/// Check that Tus-Resumable header is present and equals "1.0.0".
/// Returns Err(412) if missing or wrong.
fn check_tus_resumable(headers: &HeaderMap) -> Result<(), Box<Response>> {
    match headers.get("tus-resumable") {
        Some(v) if v == "1.0.0" => Ok(()),
        Some(v) => {
            warn!("Unsupported TUS version: {:?}", v);
            Err(Box::new(
                (
                    StatusCode::PRECONDITION_FAILED,
                    [("tus-resumable", "1.0.0")],
                    format!("Unsupported TUS version: {:?}", v),
                )
                    .into_response(),
            ))
        }
        None => Err(Box::new(
            (
                StatusCode::PRECONDITION_FAILED,
                [("tus-resumable", "1.0.0")],
                "Missing Tus-Resumable header",
            )
                .into_response(),
        )),
    }
}

/// OPTIONS — advertise TUS capabilities.
async fn tus_options(State(state): State<TusState>) -> Response {
    let algos = TusUploadManager::get_supported_checksum_algorithms().join(",");
    let max_size = state.manager.max_upload_size().to_string();

    (
        StatusCode::NO_CONTENT,
        [
            ("tus-resumable", "1.0.0"),
            ("tus-version", "1.0.0"),
            ("tus-extension", "creation,termination,checksum"),
            ("tus-checksum-algorithm", &algos),
            ("tus-max-size", &max_size),
        ],
    )
        .into_response()
}

/// POST — create a new upload session.
async fn tus_create(
    State(state): State<TusState>,
    headers: HeaderMap,
    _body: Bytes,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    // Parse Upload-Length (required)
    let upload_length = match parse_header_u64(&headers, "upload-length") {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Missing Upload-Length header",
            )
                .into_response();
        }
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                msg,
            )
                .into_response();
        }
    };

    // Parse Upload-Metadata
    let metadata = if let Some(meta_val) = headers.get("upload-metadata") {
        match meta_val.to_str() {
            Ok(s) => match decode_tus_metadata(s) {
                Ok(m) => m,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        [("tus-resumable", "1.0.0")],
                        format!("Invalid Upload-Metadata: {e}"),
                    )
                        .into_response();
                }
            },
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    "Invalid Upload-Metadata header encoding",
                )
                    .into_response();
            }
        }
    } else {
        std::collections::HashMap::new()
    };

    // Get filename from metadata, fallback to generated name
    let filename = metadata
        .get("filename")
        .cloned()
        .unwrap_or_else(|| format!("upload-{}", uuid::Uuid::new_v4()));

    // Get relative directory from metadata (optional)
    let rel_dir = metadata.get("directory").cloned().unwrap_or_default();

    // Path traversal protection
    let rel_path = if rel_dir.is_empty() {
        PathBuf::from(&filename)
    } else {
        PathBuf::from(&rel_dir).join(&filename)
    };

    if !is_safe_relative_path(&rel_path) {
        return (
            StatusCode::BAD_REQUEST,
            [("tus-resumable", "1.0.0")],
            "Invalid path: path traversal detected",
        )
            .into_response();
    }

    let target_path = state.root.join(&rel_path);
    let target_path = match state.path_policy.resolve_for_create(&target_path) {
        Ok(path) => path,
        Err(PathPolicyError::Forbidden { .. }) => {
            return (
                StatusCode::FORBIDDEN,
                [("tus-resumable", "1.0.0")],
                "Forbidden: path outside allowed roots",
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Invalid upload target path",
            )
                .into_response();
        }
    };

    info!(
        "Creating TUS upload session: target={:?}, size={}",
        target_path, upload_length
    );

    match state
        .manager
        .create_session(target_path, upload_length, metadata)
        .await
    {
        Ok(session_id) => {
            let location = format!(
                "{}/.tus-uploads/{}",
                state.prefix, session_id
            );
            info!("Created TUS session: {}", session_id);
            (
                StatusCode::CREATED,
                [
                    ("tus-resumable", "1.0.0"),
                    ("location", &location),
                ],
            )
                .into_response()
        }
        Err(e) => {
            warn!("Failed to create TUS session: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("tus-resumable", "1.0.0")],
                format!("Failed to create session: {e}"),
            )
                .into_response()
        }
    }
}

/// PATCH — upload a chunk of data.
async fn tus_patch(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    // Validate Content-Type
    if let Some(ct) = headers.get("content-type")
        && ct != "application/offset+octet-stream" {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                [("tus-resumable", "1.0.0")],
                "Content-Type must be application/offset+octet-stream",
            )
                .into_response();
        }

    // Parse Upload-Offset
    let upload_offset = match parse_header_u64(&headers, "upload-offset") {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                "Missing Upload-Offset header",
            )
                .into_response();
        }
        Err(msg) => {
            return (
                StatusCode::BAD_REQUEST,
                [("tus-resumable", "1.0.0")],
                msg,
            )
                .into_response();
        }
    };

    // Parse optional Upload-Checksum
    let checksum_info = if let Some(cksum_val) = headers.get("upload-checksum") {
        match cksum_val.to_str() {
            Ok(s) => match parse_upload_checksum(s) {
                Ok(info) => info,
                Err(msg) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        [("tus-resumable", "1.0.0")],
                        msg,
                    )
                        .into_response();
                }
            },
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    [("tus-resumable", "1.0.0")],
                    "Invalid Upload-Checksum header encoding",
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    debug!(
        "TUS upload chunk: session={}, offset={}, size={}",
        session_id,
        upload_offset,
        body.len()
    );

    // Upload the chunk
    let new_offset = match state
        .manager
        .upload_chunk_with_checksum(&session_id, upload_offset, &body, checksum_info)
        .await
    {
        Ok(off) => off,
        Err(e) => {
            let msg = e.to_string();
            let status = if msg.contains("Checksum mismatch") {
                StatusCode::from_u16(460).unwrap_or(StatusCode::BAD_REQUEST)
            } else if msg.contains("Offset mismatch") {
                StatusCode::CONFLICT
            } else if msg.contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            warn!("Failed to upload chunk: {}", msg);
            return (
                status,
                [("tus-resumable", "1.0.0")],
                msg,
            )
                .into_response();
        }
    };

    // Auto-finalize if upload is complete
    match state.manager.get_session(&session_id).await {
        Ok(session) if session.is_complete() => {
            if let Err(e) = state.manager.finalize_upload(&session_id).await {
                warn!("Failed to finalize upload: {}", e);
                let msg = e.to_string();
                if msg.contains("outside allowed roots") {
                    return (
                        StatusCode::FORBIDDEN,
                        [("tus-resumable", "1.0.0")],
                        msg,
                    )
                        .into_response();
                }
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [("tus-resumable", "1.0.0")],
                    format!("Failed to finalize upload: {msg}"),
                )
                    .into_response();
            }
            info!("TUS upload completed and finalized: {}", session_id);
        }
        _ => {}
    }

    let offset_str = new_offset.to_string();
    (
        StatusCode::NO_CONTENT,
        [
            ("tus-resumable", "1.0.0"),
            ("upload-offset", &offset_str),
        ],
    )
        .into_response()
}

/// HEAD — get upload progress.
async fn tus_head(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    match state.manager.get_session(&session_id).await {
        Ok(session) => {
            let offset_str = session.current_offset.to_string();
            let length_str = session.total_size.to_string();
            (
                StatusCode::OK,
                [
                    ("tus-resumable", "1.0.0"),
                    ("upload-offset", &offset_str),
                    ("upload-length", &length_str),
                    ("cache-control", "no-store"),
                ],
            )
                .into_response()
        }
        Err(e) => {
            let status = if e.to_string().contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                [("tus-resumable", "1.0.0")],
                e.to_string(),
            )
                .into_response()
        }
    }
}

/// DELETE — terminate an upload session.
async fn tus_delete(
    State(state): State<TusState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = check_tus_resumable(&headers) {
        return *r;
    }

    match state.manager.delete_session(&session_id).await {
        Ok(()) => {
            info!("Deleted TUS session: {}", session_id);
            (
                StatusCode::NO_CONTENT,
                [("tus-resumable", "1.0.0")],
            )
                .into_response()
        }
        Err(e) => {
            let status = if e.to_string().contains("Session not found") {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (
                status,
                [("tus-resumable", "1.0.0")],
                e.to_string(),
            )
                .into_response()
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Reject paths that contain `..` components or are absolute.
fn is_safe_relative_path(path: &std::path::Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => return false,
            std::path::Component::RootDir => return false,
            std::path::Component::Prefix(_) => return false,
            _ => {}
        }
    }
    true
}

/// Parse a header value as u64.
fn parse_header_u64(headers: &HeaderMap, name: &str) -> Result<Option<u64>, String> {
    let Some(val) = headers.get(name) else {
        return Ok(None);
    };
    let s = val
        .to_str()
        .map_err(|_| format!("Invalid {} header encoding", name))?;
    let n = s
        .parse::<u64>()
        .map_err(|_| format!("Invalid {} value: {}", name, s))?;
    Ok(Some(n))
}

/// Parse `Upload-Checksum` header: `algorithm base64checksum`
fn parse_upload_checksum(value: &str) -> Result<Option<(String, String)>, String> {
    let parts: Vec<&str> = value.trim().splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Err("Invalid Upload-Checksum format".to_string());
    }

    let algorithm = parts[0].to_lowercase();
    let checksum = parts[1];

    if !TusUploadManager::get_supported_checksum_algorithms().contains(&algorithm.as_str()) {
        return Err(format!("Unsupported checksum algorithm: {}", algorithm));
    }

    Ok(Some((algorithm, checksum.to_string())))
}
