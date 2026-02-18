//! Auto-generation of self-signed TLS certificates.
//!
//! When `--ssl-generate` is active, checks the provided certificate file:
//! - If the file does not exist → generate a new self-signed cert.
//! - If the cert is NOT trusted by the system AND validity < 1 day → regenerate.

use std::path::Path;

use anyhow::Context;
use sha2::{Digest, Sha256};
use tracing::info;
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::FromDer;

/// Examine the certificate at `cert_path` and regenerate when necessary.
///
/// Returns `true` if a new certificate was written.
pub fn maybe_regenerate_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<bool> {
    // ── File does not exist → generate unconditionally ──────────────
    if !cert_path.exists() {
        info!(
            "Certificate file not found at {}, generating self-signed cert",
            cert_path.display()
        );
        generate_to_files(cert_path, key_path)?;
        return Ok(true);
    }

    // ── Parse existing cert ────────────────────────────────────────
    let pem_data = std::fs::read(cert_path)
        .with_context(|| format!("failed to read cert: {}", cert_path.display()))?;

    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_data)
        .map_err(|e| anyhow::anyhow!("failed to parse PEM: {e}"))?;

    let (_, cert) = X509Certificate::from_der(pem.contents.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to parse X.509: {e}"))?;

    // ── Check remaining validity ───────────────────────────────────
    let remaining = cert.validity().time_to_expiration();
    let one_day = std::time::Duration::from_secs(86400);

    let expires_soon = match remaining {
        None => true,           // already expired
        Some(d) => d < one_day, // less than 1 day left
    };

    if !expires_soon {
        let days_left = remaining.map_or(0, |d| d.whole_days());
        info!("Certificate has ~{days_left} day(s) remaining, no regeneration needed");
        return Ok(false);
    }

    // ── Check system trust ─────────────────────────────────────────
    if is_trusted_by_system(&cert) {
        info!("Certificate expires soon but is system-trusted; not overwriting");
        return Ok(false);
    }

    // Not trusted + expiring → regenerate
    info!("Certificate is untrusted and expires in <1 day, regenerating");
    generate_to_files(cert_path, key_path)?;
    Ok(true)
}

// ── System trust check ─────────────────────────────────────────────

/// Returns `true` if the cert's issuer matches any system root CA subject.
fn is_trusted_by_system(cert: &X509Certificate) -> bool {
    let native_certs = rustls_native_certs::load_native_certs();

    if native_certs.certs.is_empty() {
        tracing::warn!("No system root certificates found");
        return false;
    }

    for root_der in &native_certs.certs {
        if let Ok((_, root)) = X509Certificate::from_der(root_der.as_ref()) {
            if cert.issuer() == root.subject() {
                return true;
            }
        }
    }

    false
}

// ── Certificate generation ─────────────────────────────────────────

/// Generate a self-signed ECDSA P-256 certificate and write PEM files to disk.
///
/// Parameters match [`super::selfsign::generate_self_signed`] (7-day validity,
/// SAN: localhost / 127.0.0.1 / ::1).
fn generate_to_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rcgen::{
        CertificateParams, DnType, KeyPair, PublicKeyData, SanType, PKCS_ECDSA_P256_SHA256,
    };

    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;

    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::minutes(5); // clock-skew tolerance
    params.not_after = now + ::time::Duration::days(7);

    params.distinguished_name.push(DnType::CountryName, "AU");
    params
        .distinguished_name
        .push(DnType::StateOrProvinceName, "Some-State");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Internet Widgits Pty Ltd");
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");

    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv6Addr::LOCALHOST.into()));

    let cert = params.self_signed(&key_pair)?;

    // Log fingerprints
    let cert_hash = Sha256::digest(cert.der());
    let spki_hash = Sha256::digest(key_pair.subject_public_key_info());
    info!(
        "Self-signed certificate generated:\n  Cert SHA-256: {}\n  SPKI SHA-256: {}",
        hex::encode(cert_hash),
        hex::encode(spki_hash),
    );

    // Ensure parent directories exist
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    // Write PEM
    std::fs::write(cert_path, cert.pem())
        .with_context(|| format!("failed to write cert to {}", cert_path.display()))?;
    std::fs::write(key_path, key_pair.serialize_pem())
        .with_context(|| format!("failed to write key to {}", key_path.display()))?;

    info!(
        "Certificate written to {}, key to {}",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}
