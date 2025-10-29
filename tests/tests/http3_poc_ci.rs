#![cfg(feature = "http3-experimental")]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_jwt::Ed25519KeyPair;
use aunsorm_server::{spawn_http3_poc, LedgerBackend, ServerConfig, ServerError, ServerState};

/// Ensures the HTTP/3 PoC listener comes up on the expected port and is able to
/// emit telemetry datagrams for the canary pipeline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http3_canary_listener_emits_datagrams() -> Result<(), ServerError> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let port = socket.local_addr()?.port();
    drop(socket);

    let listen = SocketAddr::from(([127, 0, 0, 1], port));
    let key_pair = Ed25519KeyPair::generate("http3-ci").expect("key generation succeeds");
    let config = ServerConfig::new(
        listen,
        "https://ci.aunsorm",
        "ci-clients",
        Duration::from_secs(300),
        false,
        key_pair,
        LedgerBackend::Memory,
        None,
    )?;
    let state = Arc::new(ServerState::try_new(config)?);

    let guard = spawn_http3_poc(listen, Arc::clone(&state))?;
    let bound = guard.local_addr()?;
    assert_eq!(bound.port(), port, "PoC listener binds to requested port");

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64;
    let batch = state
        .http3_datagram_batch(42, now)
        .await
        .expect("datagram batch is produced");
    assert!(
        !batch.is_empty(),
        "datagram batch should expose telemetry frames for monitoring"
    );

    drop(guard);
    Ok(())
}
