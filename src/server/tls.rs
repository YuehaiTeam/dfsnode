use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// Load TLS certificate chain and private key from PEM files.
fn load_certs_and_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("Failed to open cert file: {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path.display());
    }

    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("Failed to open key file: {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path.display()))?;

    Ok((certs, key))
}

/// Build a rustls ServerConfig for HTTPS (HTTP/1.1 + HTTP/2 over TLS).
pub fn build_https_config(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = load_certs_and_key(cert_path, key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build rustls ServerConfig for HTTPS")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Build a rustls ServerConfig for HTTP/3 (QUIC) — requires ALPN = "h3".
pub fn build_quic_config(cert_path: &Path, key_path: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let (certs, key) = load_certs_and_key(cert_path, key_path)?;

    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build rustls ServerConfig for QUIC")?;

    config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(Arc::new(config))
}
