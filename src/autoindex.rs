use std::collections::BTreeMap;
use std::path::Path;
use std::time::SystemTime;

use hyper::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{error, warn};

use crate::signature::{create_signature, get_expire_time};

#[derive(Debug, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
    pub is_directory: bool,
    pub size: Option<u64>,
    pub modified: Option<String>,
    pub url: String,
}

/// Generate HTML directory listing
pub async fn generate_directory_listing(
    dir_path: &Path,
    request_path: &str,
    signature_token: Option<&str>,
    signature_expire_seconds: u32,
) -> Result<String, StatusCode> {
    let mut entries = Vec::new();

    // Add parent directory link if not at root
    if request_path != "/" {
        let parent_path = if let Some(stripped) = request_path.strip_suffix('/') {
            stripped
        } else {
            request_path
        };

        let parent_url = if let Some(last_slash) = parent_path.rfind('/') {
            if last_slash == 0 {
                "/".to_string()
            } else {
                parent_path[..last_slash].to_string()
            }
        } else {
            "/".to_string()
        };

        entries.push(DirectoryEntry {
            name: "../".to_string(),
            path: parent_url.clone(),
            is_directory: true,
            size: None,
            modified: None,
            url: generate_signed_url(&parent_url, signature_token, signature_expire_seconds),
        });
    }

    // Read directory entries
    let mut dir_entries = match fs::read_dir(dir_path).await {
        Ok(entries) => entries,
        Err(e) => {
            error!("Failed to read directory {}: {}", dir_path.display(), e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut files = BTreeMap::new();
    let mut directories = BTreeMap::new();

    while let Some(entry) = dir_entries.next_entry().await.map_err(|e| {
        error!("Failed to read directory entry: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().to_string();

        // Skip hidden files starting with .
        if name.starts_with('.') {
            continue;
        }

        let metadata = match entry.metadata().await {
            Ok(meta) => meta,
            Err(e) => {
                warn!("Failed to get metadata for {}: {}", name, e);
                continue;
            }
        };

        let file_path = if request_path.ends_with('/') {
            format!("{}{}", request_path, name)
        } else {
            format!("{}/{}", request_path, name)
        };

        let modified = metadata.modified().ok().and_then(|time| {
            time.duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .and_then(|duration| {
                    let dt = chrono::DateTime::from_timestamp(duration.as_secs() as i64, 0)?;
                    Some(dt.format("%Y-%m-%d %H:%M:%S").to_string())
                })
        });

        let entry_data = DirectoryEntry {
            name: name.clone(),
            path: file_path.clone(),
            is_directory: metadata.is_dir(),
            size: if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            },
            modified,
            url: generate_signed_url(&file_path, signature_token, signature_expire_seconds),
        };

        if metadata.is_dir() {
            directories.insert(name, entry_data);
        } else {
            files.insert(name, entry_data);
        }
    }

    // Add directories first, then files
    entries.extend(directories.into_values());
    entries.extend(files.into_values());

    // Generate HTML
    let html = generate_html(request_path, &entries);
    Ok(html)
}

fn generate_signed_url(path: &str, signature_token: Option<&str>, expire_seconds: u32) -> String {
    match signature_token {
        Some(token) => {
            let expire_time = get_expire_time(expire_seconds);
            let signature = create_signature(path, expire_time, token, None);
            format!("{}?$={}", path, signature)
        }
        None => path.to_string(),
    }
}

fn generate_html(path: &str, entries: &[DirectoryEntry]) -> String {
    let title = format!("Index of {}", path);

    let mut html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Microsoft Yahei UI', Roboto, sans-serif;
            margin: 2rem;
            background-color: #eee;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .breadcrumb {{
            background: #e9ecef;
            padding: 1rem 2rem;
            font-size: 0.9rem;
            color: #6c757d;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 0;
        }}
        th {{
            background-color: #f8f9fa;
            padding: 1rem 2rem;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
            font-weight: 600;
            color: #495057;
        }}
        td {{
            padding: 0.75rem 2rem;
            border-bottom: 1px solid #dee2e6;
            vertical-align: middle;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .file-icon {{
            width: 20px;
            height: 20px;
            margin-right: 10px;
            vertical-align: middle;
        }}
        .file-name {{
            color: #007bff;
            text-decoration: none;
            font-weight: 500;
        }}
        .file-name:hover {{
            text-decoration: underline;
        }}
        .directory-name {{
            color: #6f42c1;
            text-decoration: none;
            font-weight: 500;
        }}
        .directory-name:hover {{
            text-decoration: underline;
        }}
        .file-size {{
            text-align: right;
            color: #6c757d;
            font-family: Consolas, 'SF Mono', Monaco, 'Roboto Mono', monospace;
            font-size: 0.9rem;
        }}
        .file-date {{
            color: #6c757d;
            font-family: Consolas, 'SF Mono', Monaco, 'Roboto Mono', monospace;
            font-size: 0.9rem;
        }}
        .footer {{
            padding: 1rem;
            text-align: center;
            color: #6c757d;
            font-size: 0.9rem;
            background: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="breadcrumb">{}</div>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                </tr>
            </thead>
            <tbody>"#,
        title, path
    );

    for entry in entries {
        let icon = if entry.is_directory { "📁" } else { "📄" };
        let name_class = if entry.is_directory {
            "directory-name"
        } else {
            "file-name"
        };
        let size_str = match entry.size {
            Some(size) => format_size(size),
            None => "-".to_string(),
        };
        let modified_str = entry.modified.as_deref().unwrap_or("-");

        html.push_str(&format!(
            r#"                <tr>
                    <td>
                        <span class="file-icon">{}</span>
                        <a href="{}" class="{}">{}</a>
                    </td>
                    <td class="file-size">{}</td>
                    <td class="file-date">{}</td>
                </tr>
"#,
            icon, entry.url, name_class, entry.name, size_str, modified_str
        ));
    }

    html.push_str(
        r#"            </tbody>
        </table>
        <div class="footer">
            Powered by Steambird
        </div>
    </div>
</body>
</html>"#,
    );

    html
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", size as u64, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}
