#![allow(clippy::too_many_lines)]

#[path = "../blockchain/media_ledger.rs"]
mod media_ledger;
#[path = "../blockchain/mock_ledger.rs"]
mod mock_ledger;

use media_ledger::{MediaLedgerRecord, MediaRecordError};
use mock_ledger::InMemoryLedger;

const GENESIS_TIMESTAMP: u64 = 1_728_000_000_000;

fn bootstrap_ledger() -> InMemoryLedger {
    InMemoryLedger::bootstrap(b"genesis", GENESIS_TIMESTAMP)
}

#[test]
fn sequential_media_records_anchor_to_previous_block() {
    let mut ledger = bootstrap_ledger();
    let genesis_hash = ledger.latest().block_hash;

    let first_record = MediaLedgerRecord::new(
        "hash-video-001",
        "hash-image-001",
        "hash-audio-001",
        "calibration-alpha",
        "2024-04-24T10:15:30Z",
    )
    .expect("first record is valid");
    let first_entry = first_record.clone().into_ledger_entry(1, genesis_hash);
    ledger
        .append(first_entry.clone())
        .expect("first ledger entry should be accepted");

    let second_record = MediaLedgerRecord::new(
        "hash-video-002",
        "hash-image-002",
        "hash-audio-002",
        "calibration-beta",
        "2024-04-24T10:16:05Z",
    )
    .expect("second record is valid");
    let second_entry = second_record
        .clone()
        .into_ledger_entry(2, first_entry.block_hash);
    ledger
        .append(second_entry.clone())
        .expect("second ledger entry should be accepted");

    assert_eq!(ledger.len(), 3); // includes genesis
    assert_eq!(second_entry.prev_hash, first_entry.block_hash);
    assert_eq!(ledger.latest().block_hash, second_entry.block_hash);

    let latest = ledger.latest();
    assert_eq!(latest.index, 2);
    assert_eq!(latest.payload, second_record.canonical_payload());
}

#[test]
fn invalid_timestamp_is_rejected() {
    let error = MediaLedgerRecord::new(
        "hash-video-err",
        "hash-image-err",
        "hash-audio-err",
        "calibration-gamma",
        "not-a-timestamp",
    )
    .expect_err("invalid timestamp must be rejected");
    assert_eq!(
        error,
        MediaRecordError::InvalidTimestamp {
            value: "not-a-timestamp".to_string(),
        }
    );
}

#[test]
fn empty_calibration_identifier_is_rejected() {
    let error = MediaLedgerRecord::new(
        "hash-video-err",
        "hash-image-err",
        "hash-audio-err",
        "  \t\n",
        "2024-04-24T10:20:00Z",
    )
    .expect_err("empty calibration id must be rejected");
    assert_eq!(error, MediaRecordError::EmptyField("calibration_id"));
}
