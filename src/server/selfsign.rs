use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use rcgen::{CertificateParams, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tracing::{debug, error, info};

/// How long each self-signed certificate is valid (days).
const CERT_VALIDITY_DAYS: i64 = 7;

/// Renew after this many days (renew at day 6 of 7).
const RENEWAL_DAYS: u64 = 6;

/// Dynamic certificate resolver backed by ArcSwap for atomic hot-swap.
#[derive(Debug)]
pub struct RotatingCertResolver {
    current: ArcSwap<CertifiedKey>,
}

impl RotatingCertResolver {
    /// Create a new resolver with a freshly generated self-signed certificate.
    pub fn new() -> anyhow::Result<Arc<Self>> {
        let certified_key = generate_certified_key()?;
        Ok(Arc::new(Self {
            current: ArcSwap::from(Arc::new(certified_key)),
        }))
    }

    /// Atomically replace the certificate.
    pub fn swap(&self, new_key: CertifiedKey) {
        self.current.store(Arc::new(new_key));
    }
}

impl ResolvesServerCert for RotatingCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.load_full())
    }
}

/// Generate a self-signed ECDSA P-256 certificate.
///
/// Subject: C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=localhost
/// SAN: localhost, 127.0.0.1, ::1
/// Validity: rcgen defaults (~30 days from now, sufficient since we renew every 6 days)
pub fn generate_self_signed()
    -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>
{
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;

    // Set 7-day validity (rcgen defaults to 1975-4096 if not set)
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5); // clock skew tolerance
    params.not_after = now + time::Duration::days(CERT_VALIDITY_DAYS);

    // Subject DN — match OpenSSL defaults
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

    // SAN: DNS + IP
    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv6Addr::LOCALHOST.into()));

    let cert = params.self_signed(&key_pair)?;
    let cert_der_bytes = cert.der().to_vec();
    let spki_der_bytes = key_pair.public_key_der().to_vec();

    // Print certificate fingerprints for pinning / debugging
    let cert_hash = Sha256::digest(&cert_der_bytes);
    let spki_hash = Sha256::digest(&spki_der_bytes);
    info!(
        "Self-signed certificate generated:\n  Cert SHA-256: {}\n  SPKI SHA-256: {}",
        hex::encode(cert_hash),
        hex::encode(spki_hash),
    );

    let cert_der = CertificateDer::from(cert_der_bytes);
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()));

    Ok((vec![cert_der], key_der))
}

/// Generate a [`CertifiedKey`] for use with rustls `ResolvesServerCert`.
fn generate_certified_key() -> anyhow::Result<CertifiedKey> {
    let (certs, key_der) = generate_self_signed()?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
    Ok(CertifiedKey::new(certs, signing_key))
}

/// Build a rustls [`ServerConfig`] using the rotating cert resolver (for HTTPS).
pub fn build_https_config_dynamic(
    resolver: Arc<RotatingCertResolver>,
) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Arc::new(config)
}

/// Build a quinn-compatible rustls [`ServerConfig`] using the rotating resolver.
pub fn build_quic_config_self_signed(
    resolver: &Arc<RotatingCertResolver>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver.clone());
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(config))
}

/// Spawn a background task that periodically regenerates the self-signed certificate.
///
/// - For HTTPS: swaps the [`CertifiedKey`] inside the resolver (instant for new connections).
/// - For HTTP/3: calls `endpoint.set_server_config()` with a new quinn ServerConfig.
pub fn spawn_refresh_task(
    resolver: Arc<RotatingCertResolver>,
    quinn_endpoint: Option<quinn::Endpoint>,
) -> tokio::task::JoinHandle<()> {
    let renewal_interval = Duration::from_secs(RENEWAL_DAYS * 86400);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(renewal_interval);
        interval.tick().await; // Skip immediate first tick

        loop {
            interval.tick().await;
            info!("Renewing self-signed TLS certificate...");

            match generate_certified_key() {
                Ok(new_ck) => {
                    // Swap HTTPS cert (takes effect on next TLS handshake)
                    resolver.swap(new_ck);
                    debug!("HTTPS certificate rotated");

                    // Rebuild quinn config for H3
                    if let Some(ref endpoint) = quinn_endpoint {
                        match build_quic_config_self_signed(&resolver) {
                            Ok(rustls_config) => {
                                match quinn::crypto::rustls::QuicServerConfig::try_from(
                                    rustls_config,
                                ) {
                                    Ok(quic_crypto) => {
                                        let mut transport =
                                            quinn::TransportConfig::default();
                                        transport
                                            .max_concurrent_uni_streams(16u32.into());
                                        transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
                                        let mut server_config =
                                            quinn::ServerConfig::with_crypto(Arc::new(
                                                quic_crypto,
                                            ));
                                        server_config
                                            .transport_config(Arc::new(transport));
                                        endpoint.set_server_config(Some(server_config));
                                        debug!("HTTP/3 certificate rotated");
                                    }
                                    Err(e) => {
                                        error!("Failed to create QUIC config: {e}");
                                    }
                                }
                            }
                            Err(e) => error!("Failed to rebuild TLS config: {e}"),
                        }
                    }

                    info!(
                        "Self-signed TLS certificate renewed (next renewal in {RENEWAL_DAYS} days)"
                    );
                }
                Err(e) => error!("Failed to generate new self-signed certificate: {e}"),
            }
        }
    })
}
