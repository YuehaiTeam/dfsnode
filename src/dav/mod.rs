use std::path::PathBuf;
use std::sync::Arc;

use dav_server::davpath::DavPath;
use dav_server::fs::*;

pub mod checksum;

use crate::dav::checksum::{ChecksumManager, format_oc_checksums};
use crate::path_policy::{PathPolicy, PathPolicyError};

const OC_NS: &str = "http://owncloud.org/ns";

/// A filesystem wrapper that adds OwnCloud checksum properties to WebDAV responses.
#[derive(Clone)]
pub struct ChecksumAwareFileSystem {
    inner: Box<dav_server::localfs::LocalFs>,
    checksum_manager: Arc<ChecksumManager>,
    base_path: PathBuf,
    path_policy: Arc<PathPolicy>,
}

impl ChecksumAwareFileSystem {
    pub fn new(
        inner: Box<dav_server::localfs::LocalFs>,
        checksum_manager: Arc<ChecksumManager>,
        base_path: PathBuf,
        path_policy: Arc<PathPolicy>,
    ) -> Self {
        Self {
            inner,
            checksum_manager,
            base_path,
            path_policy,
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

    fn map_policy_error(err: PathPolicyError) -> FsError {
        if err.is_forbidden() {
            FsError::Forbidden
        } else {
            FsError::NotFound
        }
    }

    fn check_existing_allowed(&self, path: &DavPath) -> Result<(), FsError> {
        let fs_path = self.resolve_path(path);
        self.path_policy
            .resolve_existing(&fs_path)
            .map(|_| ())
            .map_err(Self::map_policy_error)
    }

    fn check_create_allowed(&self, path: &DavPath) -> Result<(), FsError> {
        let fs_path = self.resolve_path(path);
        self.path_policy
            .resolve_for_create(&fs_path)
            .map(|_| ())
            .map_err(Self::map_policy_error)
    }
}

impl DavFileSystem for ChecksumAwareFileSystem {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            if options.write
                || options.append
                || options.truncate
                || options.create
                || options.create_new
            {
                self.check_create_allowed(path)?;
            } else {
                self.check_existing_allowed(path)?;
            }
            DavFileSystem::open(&*self.inner, path, options).await
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            self.check_existing_allowed(path)?;
            DavFileSystem::read_dir(&*self.inner, path, meta).await
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            self.check_existing_allowed(path)?;
            DavFileSystem::metadata(&*self.inner, path).await
        })
    }

    fn create_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.check_create_allowed(path)?;
            DavFileSystem::create_dir(&*self.inner, path).await
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.check_existing_allowed(path)?;
            DavFileSystem::remove_dir(&*self.inner, path).await
        })
    }

    fn remove_file<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.check_existing_allowed(path)?;
            DavFileSystem::remove_file(&*self.inner, path).await
        })
    }

    fn rename<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.check_existing_allowed(from)?;
            self.check_create_allowed(to)?;
            DavFileSystem::rename(&*self.inner, from, to).await
        })
    }

    fn copy<'a>(&'a self, from: &'a DavPath, to: &'a DavPath) -> FsFuture<'a, ()> {
        Box::pin(async move {
            self.check_existing_allowed(from)?;
            self.check_create_allowed(to)?;
            DavFileSystem::copy(&*self.inner, from, to).await
        })
    }

    fn have_props<'a>(
        &'a self,
        path: &'a DavPath,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        if self.check_existing_allowed(path).is_err() {
            return Box::pin(async move { false });
        }

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
        if let Err(err) = self.check_existing_allowed(path) {
            return Box::pin(async move { Err(err) });
        }

        let fs_path = self.resolve_path(path);
        let checksum_manager = self.checksum_manager.clone();

        Box::pin(async move {
            // Get base props from inner filesystem
            let mut props: Vec<DavProp> = (DavFileSystem::get_props(&*self.inner, path, do_content).await).unwrap_or_default();

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
        if let Err(err) = self.check_existing_allowed(path) {
            return Box::pin(async move { Err(err) });
        }

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
        Box::pin(async move {
            self.check_existing_allowed(path)?;
            DavFileSystem::patch_props(&*self.inner, path, patch).await
        })
    }
}
