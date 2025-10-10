use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

use aunsorm_core::{
    calib_from_text,
    kdf::{KdfPreset, KdfProfile},
    salts::Salts,
    SessionRatchet,
};
use aunsorm_packet::{
    decrypt_one_shot,
    decrypt_session,
    encrypt_one_shot,
    encrypt_session,
    AeadAlgorithm,
    DecryptParams,
    EncryptParams,
    PacketError,
    SessionDecryptParams,
    SessionEncryptParams,
    SessionMetadata,
    SessionStepOutcome,
    SessionStore,
};

/// Basit bir datagram taşıyıcısı arayüzü.
trait DatagramTransport: Send + Sync {
    fn send(&self, payload: &[u8]);
    fn try_recv(&self) -> Option<Vec<u8>>;
}

/// İki uç arasında hafıza içi loopback kanal üretir.
#[derive(Clone, Default)]
struct LoopEndpoint {
    outbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl LoopEndpoint {
    fn pair() -> (Self, Self) {
        let client_to_server = Arc::new(Mutex::new(VecDeque::new()));
        let server_to_client = Arc::new(Mutex::new(VecDeque::new()));
        let client = Self {
            outbound: Arc::clone(&client_to_server),
            inbound: Arc::clone(&server_to_client),
        };
        let server = Self {
            outbound: server_to_client,
            inbound: client_to_server,
        };
        (client, server)
    }

    fn queue_guard(queue: &Arc<Mutex<VecDeque<Vec<u8>>>>) -> std::sync::MutexGuard<'_, VecDeque<Vec<u8>>> {
        queue.lock().expect("loop transport poisoned")
    }
}

impl DatagramTransport for LoopEndpoint {
    fn send(&self, payload: &[u8]) {
        Self::queue_guard(&self.outbound).push_back(payload.to_vec());
    }

    fn try_recv(&self) -> Option<Vec<u8>> {
        Self::queue_guard(&self.inbound).pop_front()
    }
}

/// WebTransport veya WebRTC DataChannel için uçtan uca şifreleme adaptörü.
struct RealtimeAdapter<T: DatagramTransport> {
    identity: AdapterIdentity,
    ratchet: SessionRatchet,
    metadata: SessionMetadata,
    aad: Vec<u8>,
    transport: T,
    store: SessionStore,
}

#[derive(Clone, Copy)]
struct AdapterIdentity {
    protocol: &'static str,
    role: &'static str,
}

impl fmt::Display for AdapterIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.role, self.protocol)
    }
}

impl<T: DatagramTransport> RealtimeAdapter<T> {
    fn new(
        identity: AdapterIdentity,
        ratchet: SessionRatchet,
        metadata: SessionMetadata,
        aad: &[u8],
        transport: T,
    ) -> Self {
        Self {
            identity,
            ratchet,
            metadata,
            aad: aad.to_vec(),
            transport,
            store: SessionStore::new(),
        }
    }

    fn send(&mut self, plaintext: &[u8]) -> Result<SessionStepOutcome, PacketError> {
        let (packet, outcome) = encrypt_session(SessionEncryptParams {
            ratchet: &mut self.ratchet,
            metadata: &self.metadata,
            plaintext,
            aad: &self.aad,
        })?;
        let wire = packet.to_base64()?;
        self.transport.send(wire.as_bytes());
        Ok(outcome)
    }

    fn recv(&mut self) -> Result<Option<(Vec<u8>, SessionStepOutcome)>, PacketError> {
        let Some(raw) = self.transport.try_recv() else {
            return Ok(None);
        };
        let wire = String::from_utf8(raw)
            .map_err(|_| PacketError::Invalid("transport payload must be utf8"))?;
        let (ok, outcome) = decrypt_session(SessionDecryptParams {
            ratchet: &mut self.ratchet,
            metadata: &self.metadata,
            store: &mut self.store,
            aad: &self.aad,
            packet: &wire,
        })?;
        Ok(Some((ok.plaintext, outcome)))
    }
}

fn bootstrap_session(profile: KdfProfile) -> Result<(SessionMetadata, SessionRatchet), Box<dyn Error>> {
    const PASSWORD: &str = "correct horse battery staple";
    const CALIB_TEXT: &str = "Neudzulab | Prod | 2025-08";
    let (calibration, _) = calib_from_text(b"adapter-org", CALIB_TEXT)?;
    let salts = Salts::new(
        b"adapter-calib-salt".to_vec(),
        b"adapter-chain-salt".to_vec(),
        b"adapter-coord-salt".to_vec(),
    )?;
    let password_salt = b"adapter-salt!!";

    let bootstrap_packet = encrypt_one_shot(EncryptParams {
        password: PASSWORD,
        password_salt,
        calibration: &calibration,
        salts: &salts,
        plaintext: b"bootstrap", // metadata taşıyıcısı
        aad: b"bootstrap aad",
        profile,
        algorithm: AeadAlgorithm::AesGcm,
        strict: true,
        kem: None,
    })?;

    let bootstrap_b64 = bootstrap_packet.to_base64()?;
    let bootstrap_ok = decrypt_one_shot(&DecryptParams {
        password: PASSWORD,
        password_salt,
        calibration: &calibration,
        salts: &salts,
        profile,
        aad: b"bootstrap aad",
        strict: true,
        packet: &bootstrap_b64,
    })?;

    let metadata = bootstrap_ok.metadata;
    let root_key = [0x42_u8; 32];
    let session_id = [0xAA_u8; 16];
    let ratchet = SessionRatchet::new(root_key, session_id, true);
    Ok((metadata, ratchet))
}

fn run_demo(
    protocol: &'static str,
    client_aad: &[u8],
    server_aad: &[u8],
) -> Result<(), Box<dyn Error>> {
    let profile = KdfProfile::preset(KdfPreset::Medium);
    let (metadata, ratchet_seed) = bootstrap_session(profile)?;
    let (client_transport, server_transport) = LoopEndpoint::pair();

    let mut client = RealtimeAdapter::new(
        AdapterIdentity {
            protocol,
            role: "client",
        },
        SessionRatchet::from_state(ratchet_seed.export_state()),
        metadata.clone(),
        client_aad,
        client_transport,
    );

    let mut server = RealtimeAdapter::new(
        AdapterIdentity {
            protocol,
            role: "server",
        },
        ratchet_seed,
        metadata,
        server_aad,
        server_transport,
    );

    println!("\n== {protocol} demo ==");
    let hello = format!("hello from {}", client.identity);
    let client_out = client.send(hello.as_bytes())?;
    println!(
        "{} sent message_no={} session_id={:02x?}",
        client.identity,
        client_out.message_no,
        client_out.session_id
    );

    if let Some((payload, outcome)) = server.recv()? {
        println!(
            "{} received message_no={} payload={}",
            server.identity,
            outcome.message_no,
            String::from_utf8_lossy(&payload)
        );
    }

    let welcome = format!("ack from {}", server.identity);
    let server_out = server.send(welcome.as_bytes())?;
    println!(
        "{} sent message_no={} session_id={:02x?}",
        server.identity,
        server_out.message_no,
        server_out.session_id
    );

    if let Some((payload, outcome)) = client.recv()? {
        println!(
            "{} received message_no={} payload={}",
            client.identity,
            outcome.message_no,
            String::from_utf8_lossy(&payload)
        );
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run_demo("webtransport", b"wt-datagram", b"wt-datagram")?;
    run_demo("webrtc-datachannel", b"dc-reliable", b"dc-reliable")?;
    Ok(())
}
