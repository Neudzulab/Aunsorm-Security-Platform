use aunsorm_server::{
    AuditEvent, AuditOutcome, DatagramChannel, DatagramError, DatagramPayload, OtelPayload,
    QuicDatagramV1, RatchetProbe, RatchetStatus, MAX_PAYLOAD_BYTES, MAX_WIRE_BYTES,
};
use proptest::prelude::*;
use std::convert::TryFrom;

fn sample_payload(counter_count: usize) -> DatagramPayload {
    let mut otel = OtelPayload::new();
    for index in 0..counter_count {
        let value = u64::try_from(index).expect("usize fits into u64");
        otel.add_counter(format!("metric_{index}"), value);
    }
    DatagramPayload::Otel(otel)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    #[test]
    fn datagram_roundtrip_preserves_payload(counter_count in 1_usize..6) {
        let payload = sample_payload(counter_count);
        let datagram = QuicDatagramV1::new(42, 1_728_000_000_000, payload.clone()).unwrap();
        let encoded = datagram.encode().unwrap();
        prop_assert!(encoded.len() <= MAX_WIRE_BYTES);
        let decoded = QuicDatagramV1::decode(&encoded).unwrap();
        prop_assert_eq!(decoded.version, QuicDatagramV1::VERSION);
        prop_assert_eq!(decoded.channel, DatagramChannel::Telemetry);
        prop_assert_eq!(decoded.payload, payload);
    }
}

#[test]
fn oversize_payload_is_rejected() {
    let mut otel = OtelPayload::new();
    let large_name = "x".repeat(MAX_PAYLOAD_BYTES + 1);
    otel.add_counter(large_name, 1);
    let result = QuicDatagramV1::new(7, 123, DatagramPayload::Otel(otel));
    assert!(matches!(result, Err(DatagramError::PayloadTooLarge { .. })));
}

#[test]
fn audit_and_ratchet_channels_are_tagged_correctly() {
    let audit = DatagramPayload::Audit(AuditEvent {
        event_id: "event".into(),
        principal_id: "principal".into(),
        outcome: AuditOutcome::Success,
        resource: "resource".into(),
    });
    let audit_frame = QuicDatagramV1::new(90, 456, audit.clone()).unwrap();
    assert_eq!(audit_frame.channel, DatagramChannel::Audit);
    let mut session_id = [0_u8; 16];
    session_id[0] = 0xAA;
    let ratchet = DatagramPayload::Ratchet(RatchetProbe {
        session_id,
        step: 12,
        drift: -1,
        status: RatchetStatus::Advancing,
    });
    let ratchet_frame = QuicDatagramV1::new(91, 789, ratchet.clone()).unwrap();
    assert_eq!(ratchet_frame.channel, DatagramChannel::Ratchet);
    assert_eq!(ratchet_frame.payload, ratchet);
    assert_eq!(audit_frame.payload, audit);
}

#[test]
fn gauge_values_must_be_finite() {
    let mut otel = OtelPayload::new();
    let err = otel
        .add_gauge("invalid", f64::INFINITY)
        .expect_err("non-finite gauge values must be rejected");
    assert!(matches!(err, DatagramError::NonFiniteGauge { .. }));
}
