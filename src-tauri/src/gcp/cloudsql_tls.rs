//! The TLS connection to a Cloud SQL instance, made as Google's Go connector for Cloud SQL makes it: TLS 1.3 only, straight to the
//! instance's address on port 3307, without ALPN, and with the client certificate Cloud SQL signed for the connection's key as the client's
//! identity. PostgreSQL then runs inside the TLS as over plain TCP, with no SSLRequest of its own. The Go connector can also exchange a
//! metadata frame with the instance, but only when its caller asks for that; it does not by default, and this module does not at all.
//!
//! The server certificate must chain to one of the certificate authorities in the instance's connect settings: any of them, since an
//! instance whose CA hierarchy holds several certificates sends them all. It must then be made out to the instance's DNS name. One that is
//! not, such as a server certificate that names no DNS name at all, still passes when its subject common name is exactly
//! `project:instance`, as in the Go connector; the common name is read only for a certificate whose chain verified and whose one fault is
//! its name.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption, WebPkiServerVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, DnsName, ServerName, UnixTime};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, Error, InconsistentKeys, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::oid::db::rfc4519::COMMON_NAME;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::name::DirectoryString;
use zeroize::Zeroizing;

use super::cloudsql::{ConnectSettings, EphemeralCert, EphemeralKey};

/// The port an instance takes the Go connector's TLS connections on.
const PORT: u16 = 3307;
/// How long the TCP connection may take to open, and then how long the TLS handshake may take.
const TCP_LIMIT: Duration = Duration::from_secs(10);
const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
/// The server name for an instance without a usable DNS name. The `.invalid` top-level domain never names a host, so no certificate is
/// made out to it and only the common name can let a certificate through.
const NO_DNS_NAME: &str = "cloudsql.invalid";
const UNREADABLE_SERVER_CA: &str = "The server certificate authority from Cloud SQL could not be read.";
/// The parser's own words are never repeated for the client certificate: they could quote it, and it carries the access token.
const UNREADABLE_CLIENT_CERT: &str = "The client certificate from Cloud SQL could not be read.";

/// Who the server at the other end must be: the instance's DNS name when it has one, and the project and instance that make up the common
/// name of a server certificate without it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerIdentity {
    pub dns_name: Option<String>,
    pub project: String,
    pub instance: String,
}

/// The TLS configuration for a connection to the instance: TLS 1.3 only, with the aws-lc-rs provider named (this build has both of
/// rustls's providers, so rustls cannot choose one by itself), `cert` and `key` as the client's identity, and the server checked against
/// `settings.server_ca_pem` alone. A session is never resumed: the access token rides in the client certificate, so every connection
/// shows the certificate it was given rather than one an earlier session showed.
pub fn client_config(settings: &ConnectSettings, cert: &EphemeralCert, key: &EphemeralKey, identity: &ServerIdentity) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let verifier = InstanceVerifier::new(&settings.server_ca_pem, identity, &provider)?;
    let client_cert = EphemeralClientCert::new(cert, key)?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| format!("TLS 1.3 is not available: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(client_cert));
    config.resumption = Resumption::disabled();
    Ok(Arc::new(config))
}

/// The name the server certificate must be made out to: the instance's DNS name without its trailing dot, or `cloudsql.invalid` when the
/// instance has none or it is not a valid DNS name.
pub fn server_name(identity: &ServerIdentity) -> ServerName<'static> {
    let dns_name = identity.dns_name.as_deref().map(|name| name.strip_suffix('.').unwrap_or(name)).and_then(|name| DnsName::try_from(name.to_string()).ok());
    ServerName::DnsName(dns_name.unwrap_or_else(|| DnsName::try_from(NO_DNS_NAME).expect("cloudsql.invalid is a valid DNS name")))
}

/// Opens the TLS connection to the instance at `ip`: TCP to port 3307 within 10 seconds, then the handshake within 10 more. In TLS 1.3 the
/// client finishes its side of the handshake before the server has checked the client certificate, so an `Ok` stream does not mean Cloud
/// SQL accepted the certificate: a refusal arrives as an alert, and the first read or write after it fails.
pub async fn dial(ip: IpAddr, config: Arc<ClientConfig>, name: ServerName<'static>) -> io::Result<TlsStream<TcpStream>> {
    dial_within(SocketAddr::new(ip, PORT), config, name, TCP_LIMIT, HANDSHAKE_LIMIT).await
}

/// `dial` to any address, within the limits given (a test cannot listen on port 3307, and waits less).
async fn dial_within(address: SocketAddr, config: Arc<ClientConfig>, name: ServerName<'static>, tcp_limit: Duration, handshake_limit: Duration) -> io::Result<TlsStream<TcpStream>> {
    let socket = tokio::time::timeout(tcp_limit, TcpStream::connect(address))
        .await
        .map_err(|_| timed_out(format!("Cloud SQL did not answer at {address} within {tcp_limit:?}.")))??;
    // Nagle is off: the PostgreSQL messages this carries are small, and each one waits for its answer. A socket that refuses the option
    // still carries them, so the dial goes on without it.
    let _ = socket.set_nodelay(true);
    tokio::time::timeout(handshake_limit, TlsConnector::from(config).connect(name, socket))
        .await
        .map_err(|_| timed_out(format!("The TLS handshake with Cloud SQL at {address} did not finish within {handshake_limit:?}.")))?
}

fn timed_out(sentence: String) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, sentence)
}

/// The server certificate check. webpki verifies the chain against the instance's certificate authorities and then the name; a name
/// error is answered by the common name, every other verdict stands as webpki gave it, and the handshake signatures are webpki's to check.
#[derive(Debug)]
struct InstanceVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    /// `project:instance`, the common name a server certificate without the DNS name has.
    common_name: String,
}

impl InstanceVerifier {
    fn new(server_ca_pem: &str, identity: &ServerIdentity, provider: &Arc<CryptoProvider>) -> Result<InstanceVerifier, String> {
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(trust_anchors(server_ca_pem)?), Arc::clone(provider))
            .build()
            .map_err(|error| format!("The server certificate authority from Cloud SQL could not be used: {error}"))?;
        Ok(InstanceVerifier { webpki, common_name: format!("{}:{}", identity.project, identity.instance) })
    }
}

impl ServerCertVerifier for InstanceVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.webpki.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now) {
            // webpki checks the name only after the chain has verified, so a certificate with a name error is one the instance's CA issued.
            Err(Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }))
                if subject_common_name(end_entity).as_deref() == Some(self.common_name.as_str()) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            verdict => verdict,
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

/// Every certificate in the server CA text, as the trust anchors; one that cannot be read refuses the whole text.
fn trust_anchors(server_ca_pem: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(server_ca_pem.as_bytes()) {
        let certificate = certificate.map_err(|_| UNREADABLE_SERVER_CA.to_string())?;
        roots.add(certificate).map_err(|_| UNREADABLE_SERVER_CA.to_string())?;
    }
    if roots.is_empty() {
        return Err(UNREADABLE_SERVER_CA.to_string());
    }
    Ok(roots)
}

/// The common name of the certificate's subject, when the subject has exactly one and it is text.
fn subject_common_name(certificate: &CertificateDer<'_>) -> Option<String> {
    let certificate = x509_cert::Certificate::from_der(certificate.as_ref()).ok()?;
    let mut common_names = certificate.tbs_certificate.subject.0.iter().flat_map(|names| names.0.iter()).filter(|attribute| attribute.oid == COMMON_NAME);
    let (Some(common_name), None) = (common_names.next(), common_names.next()) else {
        return None;
    };
    match DirectoryString::from_der(&common_name.value.to_der().ok()?).ok()? {
        DirectoryString::PrintableString(text) => Some(text.as_str().to_string()),
        DirectoryString::TeletexString(text) => Some(text.as_str().to_string()),
        DirectoryString::Utf8String(text) => Some(text),
    }
}

/// The client's identity: the certificate Cloud SQL signed and the connection's key. `Debug` leaves the certificate out, as rustls's own
/// single-certificate resolver would not: the access token is inside it.
struct EphemeralClientCert(Arc<CertifiedKey>);

impl EphemeralClientCert {
    fn new(cert: &EphemeralCert, key: &EphemeralKey) -> Result<EphemeralClientCert, String> {
        let chain = CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>().map_err(|_| UNREADABLE_CLIENT_CERT.to_string())?;
        if chain.is_empty() {
            return Err(UNREADABLE_CLIENT_CERT.to_string());
        }
        // rustls drops the key bytes it is handed without zeroing them, so it is handed the loaded key instead, and the copy the key is
        // loaded from is zeroed as soon as loading is done.
        let signing_key = {
            let der = Zeroizing::new(key.private_der());
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&der)
        }
        .map_err(|_| "The connection's key could not be loaded.".to_string())?;
        let certified = CertifiedKey::new(chain, signing_key);
        match certified.keys_match() {
            // A key that cannot show its public half is taken on trust, as rustls takes it.
            Ok(()) | Err(Error::InconsistentKeys(InconsistentKeys::Unknown)) => Ok(EphemeralClientCert(Arc::new(certified))),
            Err(Error::InconsistentKeys(InconsistentKeys::KeyMismatch)) => Err("The client certificate from Cloud SQL is not for the connection's key.".to_string()),
            Err(_) => Err(UNREADABLE_CLIENT_CERT.to_string()),
        }
    }
}

impl fmt::Debug for EphemeralClientCert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralClientCert").finish_non_exhaustive()
    }
}

impl ResolvesClientCert for EphemeralClientCert {
    fn resolve(&self, _root_hint_subjects: &[&[u8]], _sigschemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::sign::SingleCertAndKey;
    use rustls::{ProtocolVersion, SupportedProtocolVersion};
    use std::net::Ipv4Addr;
    use std::sync::OnceLock;
    use std::time::SystemTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_rustls::TlsAcceptor;

    const PROJECT: &str = "acme-prod-123456";
    const INSTANCE: &str = "orders-pg";
    const DNS_NAME: &str = "1a2b3c4d5e6f.asia-east1.sql.goog";
    /// The instance as a legacy server certificate names it, in its common name.
    const INSTANCE_CN: &str = "acme-prod-123456:orders-pg";
    /// The limits the tests dial with: room for a handshake on a busy machine.
    const LIMIT: Duration = Duration::from_secs(10);

    type Authority = CertifiedIssuer<'static, KeyPair>;

    /// The key a connection's client certificate is made for, one for every test: making an RSA key takes a moment.
    fn ephemeral_key() -> &'static EphemeralKey {
        static KEY: OnceLock<EphemeralKey> = OnceLock::new();
        KEY.get_or_init(|| EphemeralKey::generate().expect("a key is made"))
    }

    fn subject(common_name: &str) -> DistinguishedName {
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        name
    }

    /// A certificate authority made for one test.
    fn authority(common_name: &str) -> Authority {
        let mut params = CertificateParams::default();
        params.distinguished_name = subject(common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    /// A server certificate from `ca` with `common_name` as its subject, made out to `dns_name` when there is one, and its key.
    fn server_cert(ca: &Authority, dns_name: Option<&str>, common_name: &str) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = CertificateParams::new(dns_name.map(str::to_string).into_iter().collect::<Vec<_>>()).unwrap();
        params.distinguished_name = subject(common_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, ca).unwrap();
        (cert.der().clone(), PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
    }

    /// A client certificate from `ca` for `key`, as Cloud SQL signs one for the connection's key.
    fn client_cert_for(ca: &Authority, key: &KeyPair) -> EphemeralCert {
        let mut params = CertificateParams::default();
        params.distinguished_name = subject("frank@example.com");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(key, ca).unwrap();
        EphemeralCert { cert_pem: cert.pem(), expires_at: SystemTime::now() + Duration::from_secs(3600), account: "frank@example.com".into() }
    }

    /// The client certificate for the ephemeral key.
    fn ephemeral_cert(ca: &Authority) -> EphemeralCert {
        let key = KeyPair::try_from(&ephemeral_key().private_der()).expect("rcgen reads the ephemeral key");
        client_cert_for(ca, &key)
    }

    fn settings(server_ca_pem: String) -> ConnectSettings {
        ConnectSettings { public_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), server_ca_pem, dns_name: Some(DNS_NAME.into()), database_version: "POSTGRES_16".into() }
    }

    fn identity(dns_name: Option<&str>) -> ServerIdentity {
        ServerIdentity { dns_name: dns_name.map(str::to_string), project: PROJECT.into(), instance: INSTANCE.into() }
    }

    /// What the test server saw of the one connection it took.
    struct Seen {
        client_chain: Vec<CertificateDer<'static>>,
        version: Option<ProtocolVersion>,
        alpn: Option<Vec<u8>>,
    }

    /// A TLS server on 127.0.0.1 that speaks `versions`, presents `cert` and signs with its `key`, and requires a client certificate from
    /// `client_ca`, as Cloud SQL does. It takes one connection, answers its first four bytes with `pong` and reports what it saw, or why the
    /// connection failed.
    async fn serve(
        (cert, key): (CertificateDer<'static>, PrivateKeyDer<'static>),
        client_ca: &Authority,
        versions: &[&'static SupportedProtocolVersion],
    ) -> (SocketAddr, oneshot::Receiver<io::Result<Seen>>) {
        let certified = CertifiedKey::from_der(vec![cert], key, &rustls::crypto::aws_lc_rs::default_provider()).expect("the key is the certificate's");
        serve_as(certified, client_ca, versions).await
    }

    /// `serve` with the certificate and the key it signs with given as they are, whether or not the key is the certificate's.
    async fn serve_as(
        certified: CertifiedKey,
        client_ca: &Authority,
        versions: &[&'static SupportedProtocolVersion],
    ) -> (SocketAddr, oneshot::Receiver<io::Result<Seen>>) {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_ca.der().clone()).unwrap();
        let client_verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider)).build().unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (report, seen) = oneshot::channel();
        tokio::spawn(async move {
            let outcome = async {
                let (socket, _) = listener.accept().await?;
                let mut stream = acceptor.accept(socket).await?;
                let mut ping = [0u8; 4];
                stream.read_exact(&mut ping).await?;
                stream.write_all(b"pong").await?;
                stream.flush().await?;
                let (_, connection) = stream.get_ref();
                Ok(Seen {
                    client_chain: connection.peer_certificates().map(<[_]>::to_vec).unwrap_or_default(),
                    version: connection.protocol_version(),
                    alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
                })
            };
            let _ = report.send(outcome.await);
        });
        (address, seen)
    }

    /// Dials the test server at `address` as `dial` dials Cloud SQL, with the ephemeral key.
    async fn connect(address: SocketAddr, server_ca_pem: String, cert: &EphemeralCert, identity: &ServerIdentity) -> io::Result<TlsStream<TcpStream>> {
        let config = client_config(&settings(server_ca_pem), cert, ephemeral_key(), identity).expect("the configuration builds");
        dial_within(address, config, server_name(identity), LIMIT, LIMIT).await
    }

    /// Sends `ping` and reads the answer. In TLS 1.3 the server checks the client certificate after the client's side of the handshake is
    /// done, so only a round trip shows that the server took it.
    async fn round_trip(stream: &mut TlsStream<TcpStream>) -> [u8; 4] {
        stream.write_all(b"ping").await.expect("the stream is writable");
        stream.flush().await.expect("the stream is writable");
        let mut answer = [0u8; 4];
        tokio::time::timeout(LIMIT, stream.read_exact(&mut answer)).await.expect("the answer arrives in time").expect("the server answers");
        answer
    }

    /// The rustls error behind a failed dial.
    fn tls_error(error: &io::Error) -> Option<&rustls::Error> {
        error.get_ref()?.downcast_ref::<rustls::Error>()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_san_matching_the_dns_name_is_accepted() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        // The common name is not the instance's: only the DNS name can let this certificate through.
        let (address, seen) = serve(server_cert(&server_ca, Some(DNS_NAME), "server"), &client_ca, &[&rustls::version::TLS13]).await;
        let mut stream = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(Some(DNS_NAME))).await.expect("the certificate names the DNS name");
        assert_eq!(&round_trip(&mut stream).await, b"pong");
        assert!(seen.await.unwrap().is_ok(), "the server took the connection");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_legacy_certificate_is_accepted_by_its_common_name() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let (address, seen) = serve(server_cert(&server_ca, None, INSTANCE_CN), &client_ca, &[&rustls::version::TLS13]).await;
        // Without a DNS name the server name is `cloudsql.invalid`, which no certificate names.
        let mut stream = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(None)).await.expect("the common name is the instance's");
        assert_eq!(&round_trip(&mut stream).await, b"pong");
        assert!(seen.await.unwrap().is_ok(), "the server took the connection");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrong_common_name_is_rejected() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let (address, _seen) = serve(server_cert(&server_ca, Some("9f8e7d6c5b4a.asia-east1.sql.goog"), "acme-prod-123456:billing-pg"), &client_ca, &[&rustls::version::TLS13]).await;
        let error = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(Some(DNS_NAME))).await.err().expect("another instance's certificate is refused");
        assert!(
            matches!(tls_error(&error), Some(rustls::Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }))),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_common_name_that_only_begins_with_the_instance_is_rejected() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        // `orders-pg2` begins with `orders-pg`, the instance's name: only the exact common name may pass.
        let (address, _seen) = serve(server_cert(&server_ca, None, "acme-prod-123456:orders-pg2"), &client_ca, &[&rustls::version::TLS13]).await;
        let error = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(None)).await.err().expect("another instance's certificate is refused");
        assert!(
            matches!(tls_error(&error), Some(rustls::Error::InvalidCertificate(CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }))),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_certificate_from_another_ca_is_rejected_without_the_name_fallback() {
        let (server_ca, client_ca, stranger) = (authority("Server CA"), authority("Client CA"), authority("Another CA"));
        // Everything about this certificate is right but its issuer, the common name included.
        let (address, _seen) = serve(server_cert(&stranger, Some(DNS_NAME), INSTANCE_CN), &client_ca, &[&rustls::version::TLS13]).await;
        let error = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(None)).await.err().expect("a certificate from another CA is refused");
        assert!(matches!(tls_error(&error), Some(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer))), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_that_does_not_hold_the_certificate_key_is_rejected() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        // The instance's own certificate, right in every way, but the handshake is signed with another key: whoever copied the certificate
        // cannot sign for it.
        let (cert, _key) = server_cert(&server_ca, Some(DNS_NAME), INSTANCE_CN);
        let other = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KeyPair::generate().unwrap().serialize_der()));
        let other = rustls::crypto::aws_lc_rs::sign::any_supported_type(&other).unwrap();
        let (address, _seen) = serve_as(CertifiedKey::new(vec![cert], other), &client_ca, &[&rustls::version::TLS13]).await;
        let error = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(Some(DNS_NAME))).await.err().expect("a signature by another key is refused");
        assert!(matches!(tls_error(&error), Some(rustls::Error::InvalidCertificate(CertificateError::BadSignature))), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_certificate_in_the_server_ca_bundle_is_trusted() {
        let (first, second, client_ca) = (authority("Server CA one"), authority("Server CA two"), authority("Client CA"));
        let (address, seen) = serve(server_cert(&second, Some(DNS_NAME), "server"), &client_ca, &[&rustls::version::TLS13]).await;
        let bundle = format!("{}\n{}", first.pem(), second.pem());
        let mut stream = connect(address, bundle, &ephemeral_cert(&client_ca), &identity(Some(DNS_NAME))).await.expect("the bundle's second CA is trusted too");
        assert_eq!(&round_trip(&mut stream).await, b"pong");
        assert!(seen.await.unwrap().is_ok(), "the server took the connection");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tls_13_handshake_with_the_ephemeral_client_certificate_succeeds() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        // The server would speak TLS 1.2 as well; the client asks for 1.3 only.
        let (address, seen) = serve(server_cert(&server_ca, Some(DNS_NAME), "server"), &client_ca, &[&rustls::version::TLS13, &rustls::version::TLS12]).await;
        let cert = ephemeral_cert(&client_ca);
        let mut stream = connect(address, server_ca.pem(), &cert, &identity(Some(DNS_NAME))).await.expect("the handshake completes");
        let (_, connection) = stream.get_ref();
        assert_eq!(connection.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        assert_eq!(connection.alpn_protocol(), None, "no application protocol is offered");
        assert_eq!(&round_trip(&mut stream).await, b"pong");
        let seen = seen.await.unwrap().expect("the server took the client certificate");
        let chain = CertificateDer::pem_slice_iter(cert.cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(seen.client_chain, chain, "the server saw the ephemeral certificate");
        assert_eq!(seen.version, Some(ProtocolVersion::TLSv1_3));
        assert_eq!(seen.alpn, None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_server_without_tls_13_is_refused() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let (address, _seen) = serve(server_cert(&server_ca, Some(DNS_NAME), "server"), &client_ca, &[&rustls::version::TLS12]).await;
        let error = connect(address, server_ca.pem(), &ephemeral_cert(&client_ca), &identity(Some(DNS_NAME))).await.err().expect("TLS 1.2 is refused");
        assert!(matches!(tls_error(&error), Some(rustls::Error::AlertReceived(rustls::AlertDescription::ProtocolVersion))), "{error}");
    }

    /// A listener that never answers makes the dial end at its own handshake limit, with an error rather than a panic.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_dial_to_a_silent_listener_times_out_without_panicking() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let config = client_config(&settings(server_ca.pem()), &ephemeral_cert(&client_ca), ephemeral_key(), &identity(Some(DNS_NAME))).unwrap();
        let dialled = tokio::time::timeout(
            Duration::from_secs(5),
            dial_within(address, config, server_name(&identity(Some(DNS_NAME))), Duration::from_secs(2), Duration::from_millis(300)),
        )
        .await;
        let error = dialled.expect("the dial ends at its own limit").err().expect("a silent listener is no TLS server");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
        assert_eq!(error.to_string(), format!("The TLS handshake with Cloud SQL at {address} did not finish within 300ms."));
    }

    #[test]
    fn the_server_name_is_the_dns_name_without_its_trailing_dot_else_cloudsql_invalid() {
        let dns = |name: &str| ServerName::DnsName(DnsName::try_from(name.to_string()).unwrap());
        assert_eq!(server_name(&identity(Some(DNS_NAME))), dns(DNS_NAME));
        assert_eq!(server_name(&identity(Some("1a2b3c4d5e6f.asia-east1.sql.goog."))), dns(DNS_NAME));
        for unusable in [None, Some(""), Some("."), Some("not a name"), Some("203.0.113.10"), Some(INSTANCE_CN)] {
            assert_eq!(server_name(&identity(unusable)), dns("cloudsql.invalid"), "{unusable:?}");
        }
    }

    #[test]
    fn certificates_that_cannot_be_read_are_refused_without_quoting_them() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let cert = ephemeral_cert(&client_ca);
        let build = |server_ca_pem: &str, cert: &EphemeralCert| client_config(&settings(server_ca_pem.into()), cert, ephemeral_key(), &identity(Some(DNS_NAME)));
        // A bundle with no certificate in it, and one whose certificate is not one.
        for server_ca_pem in ["no certificate here", "-----BEGIN CERTIFICATE-----\nc2VydmVyLWNh\n-----END CERTIFICATE-----\n"] {
            let error = build(server_ca_pem, &cert).err().expect("the bundle is refused");
            assert_eq!(error, "The server certificate authority from Cloud SQL could not be read.", "{server_ca_pem}");
        }
        // A real client certificate carries the access token, so nothing of what was sent may show in the sentence.
        for cert_pem in [
            "",
            "-----BEGIN CERTIFICATE-----\nY2xpZW50LWNlcnQtd2l0aC1hLXRva2Vu\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nY2xpZW50!LWNlcnQ\n-----END CERTIFICATE-----\n",
        ] {
            let unreadable = EphemeralCert { cert_pem: cert_pem.into(), ..cert.clone() };
            let error = build(&server_ca.pem(), &unreadable).err().expect("the certificate is refused");
            assert_eq!(error, "The client certificate from Cloud SQL could not be read.", "{cert_pem}");
        }
    }

    #[test]
    fn a_client_certificate_for_another_key_is_refused() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let other = client_cert_for(&client_ca, &KeyPair::generate().unwrap());
        let error = client_config(&settings(server_ca.pem()), &other, ephemeral_key(), &identity(Some(DNS_NAME))).err().expect("refused");
        assert_eq!(error, "The client certificate from Cloud SQL is not for the connection's key.");
    }

    #[test]
    fn the_configuration_prints_no_client_certificate() {
        let (server_ca, client_ca) = (authority("Server CA"), authority("Client CA"));
        let cert = ephemeral_cert(&client_ca);
        let config = client_config(&settings(server_ca.pem()), &cert, ephemeral_key(), &identity(Some(DNS_NAME))).unwrap();
        let shown = format!("{config:?}");
        let der = CertificateDer::from_pem_slice(cert.cert_pem.as_bytes()).unwrap();
        // The certificate's last bytes are its signature: no other certificate has them.
        let as_hex: String = der[der.len() - 32..].iter().map(|byte| format!("{byte:02x}")).collect();
        let pem_line = cert.cert_pem.lines().nth(3).unwrap();
        assert!(!shown.contains(&as_hex) && !shown.contains(pem_line), "{shown}");
    }
}
