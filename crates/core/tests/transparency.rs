use std::time::{Duration, UNIX_EPOCH};

use aunsorm_core::transparency::{
    unix_timestamp, KeyTransparencyLog, TransparencyEvent, TransparencyEventKind,
};

#[test]
fn append_and_verify_chain() {
    let mut log = KeyTransparencyLog::new("aunsorm-core/tests");
    let ts = unix_timestamp(UNIX_EPOCH + Duration::from_secs(1_700_000_000)).expect("timestamp");
    let first = log
        .append(TransparencyEvent::publish("kid-1", [0xAA_u8; 32], ts, None))
        .expect("first append");
    assert_eq!(first.sequence, 0);
    assert_eq!(first.event.action, TransparencyEventKind::Publish);

    let second_ts = ts + 1;
    let second = log
        .append(TransparencyEvent::publish(
            "kid-2",
            [0xBB_u8; 32],
            second_ts,
            Some("rotation".into()),
        ))
        .expect("second append");
    assert_eq!(second.sequence, 1);
    assert_ne!(first.tree_hash, second.tree_hash);

    KeyTransparencyLog::verify_chain(log.domain(), log.records()).expect("verify");
}

#[test]
fn reject_timestamp_regression() {
    let mut log = KeyTransparencyLog::new("aunsorm-core/tests");
    let ts = unix_timestamp(UNIX_EPOCH + Duration::from_secs(1_800_000_000)).expect("timestamp");
    log.append(TransparencyEvent::publish("kid-1", [0x11_u8; 32], ts, None))
        .expect("append");
    let result = log.append(TransparencyEvent::publish(
        "kid-2",
        [0x22_u8; 32],
        ts - 1,
        None,
    ));
    assert!(result.is_err());
}
