//! Auto-generation of self-signed TLS certificates.
//!
//! When `--ssl-generate` is active, checks the provided certificate file:
//! - If the file does not exist → generate a new self-signed cert.
//! - If the certificate/private-key pair is missing or inconsistent → regenerate.
//! - If the cert is NOT trusted by the system AND validity < 1 day → regenerate.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::FromDer;

use super::selfsign::RotatingCertResolver;

pub enum PreparedTlsIdentity {
    Files,
    InMemory(Arc<RotatingCertResolver>),
}

struct GeneratedCertMaterial {
    cert_pem: String,
    key_pem: String,
    certs: Vec<CertificateDer<'static>>,
    key_der: PrivateKeyDer<'static>,
}

/// Examine the certificate at `cert_path` and regenerate when necessary.
///
/// Returns which TLS identity should be used for this process.
pub fn prepare_tls_identity(cert_path: &Path, key_path: &Path) -> anyhow::Result<PreparedTlsIdentity> {
    let cert_exists = cert_path.exists();
    let key_exists = key_path.exists();
    let fallback_allowed = cert_exists || key_exists;
    let bootstrap_required = !cert_exists && !key_exists;

    // ── File does not exist → generate unconditionally ──────────────
    if !cert_exists {
        info!(
            "Certificate file not found at {}, generating self-signed cert",
            cert_path.display()
        );
        let material = generate_cert_material()?;
        if bootstrap_required {
            persist_generated_pair(cert_path, key_path, &material)?;
            return Ok(PreparedTlsIdentity::Files);
        }
        return persist_or_fallback(cert_path, key_path, &material, fallback_allowed);
    }

    if !key_exists {
        info!(
            "Private key file not found at {}, regenerating certificate pair",
            key_path.display()
        );
        let material = generate_cert_material()?;
        return persist_or_fallback(cert_path, key_path, &material, fallback_allowed);
    }

    let needs_regeneration = if let Err(err) = super::tls::validate_cert_key_pair(cert_path, key_path) {
        info!(
            error = %format!("{err:#}"),
            "Certificate and private key are inconsistent, regenerating"
        );
        true
    } else {
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
            None => true,
            Some(d) => d < one_day,
        };

        if !expires_soon {
            let days_left = remaining.map_or(0, |d| d.whole_days());
            info!("Certificate has ~{days_left} day(s) remaining, no regeneration needed");
            return Ok(PreparedTlsIdentity::Files);
        }

        if is_trusted_by_system(&cert) {
            info!("Certificate expires soon but is system-trusted; not overwriting");
            return Ok(PreparedTlsIdentity::Files);
        }

        info!("Certificate is untrusted and expires in <1 day, regenerating");
        true
    };

    if needs_regeneration {
        let material = generate_cert_material()?;
        return persist_or_fallback(cert_path, key_path, &material, fallback_allowed);
    }

    Ok(PreparedTlsIdentity::Files)
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
fn generate_cert_material() -> anyhow::Result<GeneratedCertMaterial> {
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

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()));

    Ok(GeneratedCertMaterial {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        certs: vec![cert_der],
        key_der,
    })
}

fn persist_or_fallback(
    cert_path: &Path,
    key_path: &Path,
    material: &GeneratedCertMaterial,
    fallback_allowed: bool,
) -> anyhow::Result<PreparedTlsIdentity> {
    match persist_generated_pair(cert_path, key_path, material) {
        Ok(()) => Ok(PreparedTlsIdentity::Files),
        Err(err) if fallback_allowed => {
            warn!(
                error = %format!("{err:#}"),
                "Failed to persist regenerated certificate pair; using in-memory certificate for this process"
            );
            let resolver = RotatingCertResolver::from_parts(material.certs.clone(), material.key_der.clone_key())?;
            Ok(PreparedTlsIdentity::InMemory(resolver))
        }
        Err(err) => Err(err),
    }
}

fn persist_generated_pair(
    cert_path: &Path,
    key_path: &Path,
    material: &GeneratedCertMaterial,
) -> anyhow::Result<()> {
    // Ensure parent directories exist when possible.
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let previous_key = std::fs::read(key_path).ok();
    let previous_cert = std::fs::read(cert_path).ok();

    // Write key first; if this fails we leave the old cert untouched.
    std::fs::write(key_path, material.key_pem.as_bytes())
        .with_context(|| format!("failed to write key to {}", key_path.display()))?;

    if let Err(err) = std::fs::write(cert_path, material.cert_pem.as_bytes()) {
        if let Some(old_cert) = previous_cert {
            let _ = std::fs::write(cert_path, old_cert);
        } else {
            let _ = std::fs::remove_file(cert_path);
        }
        if let Some(old_key) = previous_key {
            let _ = std::fs::write(key_path, old_key);
        } else {
            let _ = std::fs::remove_file(key_path);
        }
        return Err(anyhow::anyhow!("failed to write cert to {}: {err}", cert_path.display()));
    }

    info!(
        "Certificate written to {}, key to {}",
        cert_path.display(),
        key_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use sha2::Digest;

    use super::{PreparedTlsIdentity, prepare_tls_identity};

    fn temp_file_path(name: &str) -> PathBuf {
        let unique = uuid::Uuid::new_v4();
        std::env::temp_dir().join(format!("dfsnode-ssl-generate-{name}-{unique}.pem"))
    }

    fn write_mismatched_pair(cert_path: &std::path::Path, key_path: &std::path::Path) {
        let cert_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate cert key");
        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("generate wrong key");
        let params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&cert_key).expect("self sign cert");

        std::fs::write(cert_path, cert.pem()).expect("write cert");
        std::fs::write(key_path, wrong_key.serialize_pem()).expect("write wrong key");
    }

    #[test]
    fn regenerates_when_key_file_is_missing() {
        let cert_path = temp_file_path("missing-cert");
        let key_path = temp_file_path("missing-key");

        write_mismatched_pair(&cert_path, &key_path);
        std::fs::remove_file(&key_path).expect("remove key");

        let prepared = prepare_tls_identity(&cert_path, &key_path).expect("prepare pair");
        assert!(matches!(prepared, PreparedTlsIdentity::Files));
        super::super::tls::validate_cert_key_pair(&cert_path, &key_path)
            .expect("regenerated pair should be valid");

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn regenerates_when_cert_and_key_do_not_match() {
        let cert_path = temp_file_path("mismatch-cert");
        let key_path = temp_file_path("mismatch-key");

        write_mismatched_pair(&cert_path, &key_path);
        let old_cert_hash = sha2::Sha256::digest(std::fs::read(&cert_path).expect("read old cert"));

        let prepared = prepare_tls_identity(&cert_path, &key_path).expect("prepare pair");
        assert!(matches!(prepared, PreparedTlsIdentity::Files));

        let new_cert_hash = sha2::Sha256::digest(std::fs::read(&cert_path).expect("read new cert"));
        assert_ne!(old_cert_hash[..], new_cert_hash[..], "certificate should be replaced");
        super::super::tls::validate_cert_key_pair(&cert_path, &key_path)
            .expect("regenerated pair should be valid");

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[test]
    fn falls_back_to_memory_for_existing_deployment_when_persist_fails() {
        let cert_path = temp_file_path("fallback-cert");
        let key_dir = std::env::temp_dir().join(format!("dfsnode-ssl-generate-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&key_dir).expect("create key dir");

        write_mismatched_pair(&cert_path, &key_dir.join("placeholder.pem"));

        let prepared = prepare_tls_identity(&cert_path, &key_dir).expect("prepare with fallback");
        assert!(matches!(prepared, PreparedTlsIdentity::InMemory(_)));

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_dir_all(&key_dir);
    }

    #[test]
    fn falls_back_to_memory_when_cert_is_missing_but_key_exists() {
        let cert_path = temp_file_path("missing-existing-cert");
        let key_dir = std::env::temp_dir().join(format!("dfsnode-ssl-generate-dir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&key_dir).expect("create key dir");
        let key_path = key_dir.join("existing-key.pem");

        write_mismatched_pair(&cert_path, &key_path);
        std::fs::remove_file(&cert_path).expect("remove cert");

        let prepared = prepare_tls_identity(&cert_path, &key_dir).expect("prepare with fallback");
        assert!(matches!(prepared, PreparedTlsIdentity::InMemory(_)));

        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_dir_all(&key_dir);
    }
}
