use std::path::PathBuf;

use moka::future::Cache;
use tokio::time::Duration;

// File system cache constants - 优化缓存配置
const FS_CACHE_SIZE: usize = 262144; // 增加到 256K
const FS_CACHE_TTL_SECS: u64 = 300; // 增加到 5 分钟

// File system metadata enum
#[derive(Debug, Clone)]
pub enum FileSystemStatus {
    NotExists,
    File,
    Directory,
}

// Lock-free Moka cache wrapper
pub struct FileSystemCache {
    cache: Cache<PathBuf, FileSystemStatus>,
}

impl FileSystemCache {
    pub fn new() -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(FS_CACHE_SIZE as u64)
                .time_to_live(Duration::from_secs(FS_CACHE_TTL_SECS))
                .build(),
        }
    }

    pub async fn get(&self, path: &PathBuf) -> Option<FileSystemStatus> {
        self.cache.get(path).await
    }

    pub async fn put(&self, path: PathBuf, status: FileSystemStatus) {
        self.cache.insert(path, status).await;
    }

    pub async fn get_or_fetch<F, Fut>(&self, path: PathBuf, fetch_fn: F) -> FileSystemStatus
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = FileSystemStatus>,
    {
        // Try to get from cache first
        if let Some(status) = self.get(&path).await {
            return status;
        }

        // Cache miss or expired, fetch from filesystem
        let status = fetch_fn().await;

        // Update cache
        self.put(path, status.clone()).await;

        status
    }
}

pub async fn check_file_status(path: &PathBuf) -> FileSystemStatus {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => {
            if metadata.is_dir() {
                FileSystemStatus::Directory
            } else {
                FileSystemStatus::File
            }
        }
        Err(_) => FileSystemStatus::NotExists,
    }
}
