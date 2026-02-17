use std::path::PathBuf;
use std::sync::Arc;

use dav_server::davpath::DavPath;
use dav_server::fs::*;

use crate::checksum::{ChecksumManager, format_oc_checksums};

const OC_NS: &str = "http://owncloud.org/ns";

/// A filesystem wrapper that adds OwnCloud checksum properties to WebDAV responses.
#[derive(Clone)]
pub struct ChecksumAwareFileSystem {
    inner: Box<dav_server::localfs::LocalFs>,
    checksum_manager: Arc<ChecksumManager>,
    base_path: PathBuf,
}

impl ChecksumAwareFileSystem {
    pub fn new(
        inner: Box<dav_server::localfs::LocalFs>,
        checksum_manager: Arc<ChecksumManager>,
        base_path: PathBuf,
    ) -> Self {
        Self {
            inner,
            checksum_manager,
            base_path,
        }
    }

    /// Convert a DavPath (URL path) to an actual filesystem path
    fn resolve_path(&self, path: &DavPath) -> PathBuf {
        let url_path = path.as_url_string();
        let relative = url_path.trim_start_matches('/');
        if relative.is_empty() {
            self.base_path.clone()
        } else {
            self.base_path.join(relative)
        }
    }
}

impl DavFileSystem for ChecksumAwareFileSystem {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        DavFileSystem::open(&*self.inner, path, options)
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        DavFileSystem::read_dir(&*self.inner, path, meta)
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        DavFileSystem::metadata(&*self.inner, path)
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        DavFileSystem::create_dir(&*self.inner, path)
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        DavFileSystem::remove_dir(&*self.inner, path)
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        DavFileSystem::remove_file(&*self.inner, path)
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        DavFileSystem::rename(&*self.inner, from, to)
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        DavFileSystem::copy(&*self.inner, from, to)
    }

    fn have_props<'a>(
        &'a self,
        path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        let fs_path = self.resolve_path(path);
        Box::pin(async move {
            match tokio::fs::metadata(&fs_path).await {
                Ok(meta) => meta.is_file(),
                Err(_) => false,
            }
        })
    }

    fn get_props<'a>(
        &'a self,
        path: &'a DavPath,
        do_content: bool,
    ) -> FsFuture<'a, Vec<DavProp>> {
        let fs_path = self.resolve_path(path);
        let checksum_manager = self.checksum_manager.clone();

        Box::pin(async move {
            // Get base props from inner filesystem
            let mut props = match DavFileSystem::get_props(&*self.inner, path, do_content).await {
                Ok(p) => p,
                Err(_) => Vec::new(),
            };

            // Add checksum property if this is a file with checksums
            if let Ok(Some(checksums)) = checksum_manager.get_checksums(&fs_path).await {
                let checksum_str = format_oc_checksums(&checksums);
                let xml = format!(
                    "<oc:checksums xmlns:oc=\"{OC_NS}\">{checksum_str}</oc:checksums>"
                );
                props.push(DavProp {
                    name: "checksums".to_string(),
                    prefix: Some("oc".to_string()),
                    namespace: Some(OC_NS.to_string()),
                    xml: Some(xml.into_bytes()),
                });
            }

            Ok(props)
        })
    }

    fn get_prop<'a>(
        &'a self,
        path: &'a DavPath,
        prop: DavProp,
    ) -> FsFuture<'a, Vec<u8>> {
        let fs_path = self.resolve_path(path);
        let checksum_manager = self.checksum_manager.clone();

        Box::pin(async move {
            // Check if this is an oc:checksums request
            let is_checksum_prop = prop.name == "checksums"
                && prop.namespace.as_deref() == Some(OC_NS);

            if is_checksum_prop {
                if let Ok(Some(checksums)) = checksum_manager.get_checksums(&fs_path).await {
                    let checksum_str = format_oc_checksums(&checksums);
                    let xml = format!(
                        "<oc:checksums xmlns:oc=\"{OC_NS}\">{checksum_str}</oc:checksums>"
                    );
                    return Ok(xml.into_bytes());
                }
                return Err(FsError::NotFound);
            }

            // Delegate other props to inner
            DavFileSystem::get_prop(&*self.inner, path, prop).await
        })
    }

    fn patch_props<'a>(
        &'a self,
        path: &'a DavPath,
        patch: Vec<(bool, DavProp)>,
    ) -> FsFuture<'a, Vec<(http::StatusCode, DavProp)>> {
        DavFileSystem::patch_props(&*self.inner, path, patch)
    }
}
