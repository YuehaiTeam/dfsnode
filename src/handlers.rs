use std::sync::Arc;
use std::time::Instant;

use hyper::body::Bytes;
use hyper::http::StatusCode;
use hyper::{Method, Request, Response};
use prometheus::{Encoder, TextEncoder};

use crate::app::AppState;
use crate::autoindex::generate_directory_listing;
use crate::cache::{FileSystemStatus, check_file_status};
use crate::response::ResBody;
use crate::signature::verify_signature;

pub async fn handle_request(
    state: AppState,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<ResBody>, std::io::Error> {
    let method = req.method();
    let uri = req.uri();
    let path = uri.path();

    // Handle Prometheus metrics endpoint
    if path == "/-/metrics" {
        return handle_metrics_request(&state, req).await;
    }

    if method != Method::GET && method != Method::HEAD {
        let response = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(ResBody::Empty)
            .unwrap();
        return Ok(response);
    }

    // Find matching path config - use optimized path lookup
    let path_config = {
        let config = state.config.load();
        config.find_path_config(path).cloned()
    };
    // Check signature if required
    if let Some(ref path_cfg) = path_config {
        if let Some(ref signature_token) = path_cfg.signature {
            let range_header = req.headers().get("range").and_then(|h| h.to_str().ok());
            if let Err(err_msg) = verify_signature(path, uri.query(), signature_token, range_header)
            {
                let response = Response::builder()
                    .status(err_msg)
                    .body(ResBody::Empty)
                    .unwrap();
                return Ok(response);
            }
        }
    }

    // Check if autoindex is enabled for directory listing
    let enable_autoindex = path_config
        .as_ref()
        .and_then(|pc| pc.autoindex)
        .unwrap_or(false);

    // Use cached file system status check
    let file_path = state.data_dir.join(path.trim_start_matches('/'));
    let file_path_clone = file_path.clone();

    let fs_status = state
        .fs_cache
        .get_or_fetch(file_path.clone(), || async move {
            check_file_status(&file_path_clone).await
        })
        .await;

    // Handle different file system statuses
    match fs_status {
        FileSystemStatus::NotExists => {
            let response = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(ResBody::Empty)
                .unwrap();
            return Ok(response);
        }
        FileSystemStatus::Directory => {
            if !enable_autoindex {
                let response = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(ResBody::Empty)
                    .unwrap();
                return Ok(response);
            }
            // Generate directory listing with signatures if required
            let signature_token = path_config.as_ref().and_then(|pc| pc.signature.as_deref());

            let signature_expire_seconds = path_config
                .as_ref()
                .and_then(|pc| pc.signature_expire_seconds)
                .unwrap_or(3600); // 默认1小时

            match generate_directory_listing(
                &file_path,
                path,
                signature_token,
                signature_expire_seconds,
            )
            .await
            {
                Ok(html) => {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(ResBody::Bytes(Bytes::from(html)))
                        .unwrap();
                    return Ok(response);
                }
                Err(status) => {
                    let response = Response::builder()
                        .status(status)
                        .body(ResBody::Empty)
                        .unwrap();
                    return Ok(response);
                }
            }
        }
        FileSystemStatus::File => {
            // File exists, continue to serve
        }
    }

    // 在调用 serve 前克隆需要的信息
    let method_for_logging = method.clone();
    let uri_for_logging = uri.clone();

    // Use hyper_staticfile to serve the file/directory
    match state.static_service.serve(req).await {
        Ok(response) => {
            let status = response.status();
            // 对于文件响应，使用带日志的包装器来记录完整下载时间
            let response = response.map(|res| ResBody::Static {
                inner: res,
                start_time: Instant::now(), // 记录开始时间
                metrics: Arc::new(crate::response::StaticMetrics {
                    method: method_for_logging,
                    uri: uri_for_logging,
                    status,
                }),
                bytes_sent: 0, // 初始化字节数为0
            });
            Ok(response)
        }
        Err(err) => Err(err),
    }
}

pub async fn handle_metrics_request(
    state: &AppState,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<ResBody>, std::io::Error> {
    // Check Authorization header using precomputed auth header
    let auth_valid = {
        let config = state.config.load();
        if let Some(expected_auth) = config.prometheus_auth_header.as_ref() {
            let auth_header = req.headers().get("Authorization");
            match auth_header {
                Some(header_value) => {
                    let header_str = header_value.to_str().unwrap_or("");
                    header_str == expected_auth
                }
                None => false,
            }
        } else {
            // No token configured, allow access
            true
        }
    };

    if !auth_valid {
        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("Content-Type", "text/plain")
            .body(ResBody::Empty)
            .unwrap();
        return Ok(response);
    }

    // Generate metrics
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    if encoder.encode(&metric_families, &mut buffer).is_err() {
        let response = Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "text/plain")
            .body(ResBody::Empty)
            .unwrap();
        return Ok(response);
    }

    // 使用 Bytes 避免字符串分配
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(ResBody::Bytes(Bytes::from(buffer)))
        .unwrap();

    Ok(response)
}
