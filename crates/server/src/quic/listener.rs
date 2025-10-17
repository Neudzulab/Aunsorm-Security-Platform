use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, Method, Response as HttpResponse, StatusCode};
use bytes::Bytes;
use h3::server::{Connection as H3Connection, RequestResolver};
use h3_quinn::quinn::{
    self,
    crypto::rustls::QuicServerConfig,
    rustls::{self as quinn_rustls, pki_types::CertificateDer, pki_types::PrivateKeyDer},
    VarInt,
};
use h3_quinn::Connection as H3QuinnConnection;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{info, warn};

use crate::error::ServerError;
use crate::quic::datagram::{DatagramError, QuicDatagramV1};
use crate::state::ServerState;

const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);
const ALT_SVC_MAX_AGE: u32 = 3600;

/// HTTP/3 `PoC` dinleyicisini canlı tutan koruyucu.
pub struct Http3PocGuard {
    endpoint: quinn::Endpoint,
    driver: JoinHandle<()>,
}

impl Drop for Http3PocGuard {
    fn drop(&mut self) {
        self.endpoint
            .close(VarInt::from_u32(0), b"http3-poc-shutdown");
        self.driver.abort();
    }
}

/// HTTP/3 `PoC` dinleyicisini başlatır.
///
/// # Errors
///
/// Sertifika üretimi, QUIC yapılandırması veya dinleyici kurulumu
/// başarısız olursa [`ServerError`] döner.
pub fn spawn_http3_poc(
    listen: SocketAddr,
    state: Arc<ServerState>,
) -> Result<Http3PocGuard, ServerError> {
    let (cert, key) = generate_ephemeral_cert(listen)?;
    let server_config = build_server_config(cert, key)?;
    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    info!(address = %listen, "HTTP/3 PoC dinleyicisi başlatıldı");
    let driver_endpoint = endpoint.clone();
    let driver = tokio::spawn(async move {
        run_accept_loop(driver_endpoint, state).await;
    });
    Ok(Http3PocGuard { endpoint, driver })
}

fn generate_ephemeral_cert(
    listen: SocketAddr,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ServerError> {
    let mut params = CertificateParams::new(vec!["localhost".to_owned()]);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "aunsorm-http3-poc");
    dn.push(DnType::OrganizationName, "Aunsorm");
    params.distinguished_name = dn;
    params
        .subject_alt_names
        .push(SanType::DnsName("aunsorm.local".to_owned()));
    params
        .subject_alt_names
        .push(SanType::IpAddress(listen.ip()));
    let cert = Certificate::from_params(params).map_err(|err| {
        ServerError::Configuration(format!("HTTP/3 sertifikası üretilemedi: {err}"))
    })?;
    let cert_der = cert.serialize_der().map_err(|err| {
        ServerError::Configuration(format!("HTTP/3 sertifikası serileştirilemedi: {err}"))
    })?;
    let key_der = cert.serialize_private_key_der();
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|err| ServerError::Configuration(format!("HTTP/3 anahtarı geçersiz: {err}")))?;
    Ok((cert, key))
}

fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, ServerError> {
    let mut tls_config = quinn_rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|err| {
            ServerError::Configuration(format!("rustls yapılandırması başarısız: {err}"))
        })?;
    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![b"h3".to_vec(), b"h3-29".to_vec(), b"http/1.1".to_vec()];
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config).map_err(|err| {
            ServerError::Configuration(format!("QUIC TLS yapılandırması başarısız: {err}"))
        })?,
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(30)));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    transport.datagram_send_buffer_size(64 * 1024);
    server_config.transport_config(Arc::new(transport));
    Ok(server_config)
}

async fn run_accept_loop(endpoint: quinn::Endpoint, state: Arc<ServerState>) {
    while let Some(connecting) = endpoint.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    info!(remote = %conn.remote_address(), "HTTP/3 bağlantısı kuruldu");
                    if let Err(err) = handle_connection(conn, state).await {
                        warn!(error = %err, "HTTP/3 bağlantısı hatayla kapandı");
                    }
                }
                Err(err) => {
                    warn!(error = %err, "HTTP/3 bağlantısı kabul edilemedi");
                }
            }
        });
    }
}

async fn handle_connection(
    conn: quinn::Connection,
    state: Arc<ServerState>,
) -> Result<(), Http3Error> {
    let h3_conn = H3Connection::new(H3QuinnConnection::new(conn.clone()))
        .await
        .map_err(|err| Http3Error::Handshake(err.to_string()))?;
    let request_state = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(err) = stream_datagrams(conn, request_state).await {
            warn!(error = %err, "HTTP/3 datagram akışı durdu");
        }
    });
    drive_requests(h3_conn, state).await
}

async fn drive_requests(
    mut connection: H3Connection<H3QuinnConnection, Bytes>,
    state: Arc<ServerState>,
) -> Result<(), Http3Error> {
    loop {
        match connection.accept().await {
            Ok(Some(resolver)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = handle_request(resolver, state).await {
                        warn!(error = %err, "HTTP/3 isteği işlenemedi");
                    }
                });
            }
            Ok(None) => return Ok(()),
            Err(err) => return Err(Http3Error::Accept(err.to_string())),
        }
    }
}

async fn handle_request(
    resolver: RequestResolver<H3QuinnConnection, Bytes>,
    state: Arc<ServerState>,
) -> Result<(), Http3Error> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .map_err(|err| Http3Error::Resolve(err.to_string()))?;
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let response = match (method, path.as_str()) {
        (Method::GET, "/health") => {
            let body = serde_json::json!({
                "status": "ok",
                "http3": true,
                "alt_svc_max_age": ALT_SVC_MAX_AGE,
            });
            build_json_response(StatusCode::OK, &body)
        }
        (Method::GET, "/metrics") => {
            let body = render_metrics(&state)
                .await
                .map_err(|err| Http3Error::Telemetry(err.to_string()))?;
            build_plain_response(StatusCode::OK, body)
        }
        _ => {
            let body = serde_json::json!({
                "error": "not_found",
                "message": "HTTP/3 uç noktası tanınmadı",
            });
            build_json_response(StatusCode::NOT_FOUND, &body)
        }
    }?;

    stream
        .send_response(response.head)
        .await
        .map_err(|err| Http3Error::Response(err.to_string()))?;
    if let Some(body) = response.body {
        stream
            .send_data(body)
            .await
            .map_err(|err| Http3Error::Body(err.to_string()))?;
    }
    stream
        .finish()
        .await
        .map_err(|err| Http3Error::Finish(err.to_string()))?;
    Ok(())
}

struct PreparedResponse {
    head: HttpResponse<()>,
    body: Option<Bytes>,
}

/// JSON içerikli HTTP yanıtını hazırlar.
///
/// # Errors
///
/// Yanıt gövdesi serileştirilemezse veya başlık inşası başarısız olursa
/// [`Http3Error::Encoding`] döner.
fn build_json_response(
    status: StatusCode,
    body: &serde_json::Value,
) -> Result<PreparedResponse, Http3Error> {
    let serialized =
        serde_json::to_vec(body).map_err(|err| Http3Error::Encoding(err.to_string()))?;
    let response = HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(())
        .map_err(|err| Http3Error::Encoding(err.to_string()))?;
    Ok(PreparedResponse {
        head: response,
        body: Some(Bytes::from(serialized)),
    })
}

/// Düz metin içerikli HTTP yanıtını hazırlar.
///
/// # Errors
///
/// Yanıt başlığı oluşturulamazsa [`Http3Error::Encoding`] döner.
fn build_plain_response(status: StatusCode, body: String) -> Result<PreparedResponse, Http3Error> {
    let response = HttpResponse::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(())
        .map_err(|err| Http3Error::Encoding(err.to_string()))?;
    Ok(PreparedResponse {
        head: response,
        body: Some(Bytes::from(body)),
    })
}

async fn render_metrics(state: &ServerState) -> Result<String, ServerError> {
    let now = std::time::SystemTime::now();
    let pending = state.auth_request_count().await;
    let active = state.active_token_count(now).await?;
    let sfu = state.sfu_context_count(now).await;
    let mdm = state.registered_device_count()?;
    Ok(format!(
        "# HELP aunsorm_pending_auth_requests Bekleyen PKCE yetkilendirme istekleri\n# TYPE aunsorm_pending_auth_requests gauge\naunsorm_pending_auth_requests {pending}\n# HELP aunsorm_active_tokens Aktif erişim belirteci sayısı\n# TYPE aunsorm_active_tokens gauge\naunsorm_active_tokens {active}\n# HELP aunsorm_sfu_contexts Aktif SFU oturum bağlamı sayısı\n# TYPE aunsorm_sfu_contexts gauge\naunsorm_sfu_contexts {sfu}\n# HELP aunsorm_mdm_registered_devices Kayıtlı MDM cihazı sayısı\n# TYPE aunsorm_mdm_registered_devices gauge\naunsorm_mdm_registered_devices {mdm}\n"
    ))
}

async fn stream_datagrams(
    conn: quinn::Connection,
    state: Arc<ServerState>,
) -> Result<(), DatagramLoopError> {
    let mut ticker = interval(TELEMETRY_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sequence = 0_u32;
    loop {
        ticker.tick().await;
        sequence = sequence.wrapping_add(1);
        let timestamp = QuicDatagramV1::now_timestamp_ms()?;
        let frames = state
            .http3_datagram_batch(sequence, timestamp)
            .await
            .map_err(|err| DatagramLoopError::State(err.to_string()))?;
        for frame in frames {
            let encoded = frame.encode()?;
            if encoded.is_empty() {
                continue;
            }
            match conn.send_datagram(Bytes::from(encoded)) {
                Ok(()) => {}
                Err(quinn::SendDatagramError::UnsupportedByPeer) => {
                    return Err(DatagramLoopError::Unsupported);
                }
                Err(quinn::SendDatagramError::ConnectionLost(_)) => {
                    return Err(DatagramLoopError::Closed);
                }
                Err(err) => return Err(DatagramLoopError::Send(err)),
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Http3Error {
    #[error("HTTP/3 el sıkışması başarısız: {0}")]
    Handshake(String),
    #[error("HTTP/3 isteği kabul edilemedi: {0}")]
    Accept(String),
    #[error("HTTP/3 isteği çözülemedi: {0}")]
    Resolve(String),
    #[error("HTTP/3 yanıtı gönderilemedi: {0}")]
    Response(String),
    #[error("HTTP/3 veri gönderimi başarısız: {0}")]
    Body(String),
    #[error("HTTP/3 akışı kapatılamadı: {0}")]
    Finish(String),
    #[error("HTTP/3 içeriği kodlanamadı: {0}")]
    Encoding(String),
    #[error("HTTP/3 telemetri hazırlanamadı: {0}")]
    Telemetry(String),
}

#[derive(Debug, thiserror::Error)]
enum DatagramLoopError {
    #[error("HTTP/3 zaman damgası üretilemedi: {0}")]
    Timestamp(#[from] DatagramError),
    #[error("HTTP/3 telemetri üretilemedi: {0}")]
    State(String),
    #[error("HTTP/3 datagram desteği istemci tarafından reddedildi")]
    Unsupported,
    #[error("HTTP/3 bağlantısı kapandı")]
    Closed,
    #[error("HTTP/3 datagram gönderilemedi: {0}")]
    Send(quinn::SendDatagramError),
}
