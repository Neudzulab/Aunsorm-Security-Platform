use super::mock_ledger::{payload_digest, InMemoryLedger, LedgerBackend, LedgerEntry, LedgerError};

#[derive(Clone, Debug)]
pub struct IntegrityCase {
    pub description: &'static str,
    pub entries: Vec<LedgerEntry>,
    pub expected_error: Option<LedgerError>,
}

fn build_sequence() -> (InMemoryLedger, Vec<LedgerEntry>) {
    let ledger = InMemoryLedger::bootstrap(b"genesis", 1_728_000_000_000);
    let genesis_hash = ledger.latest().block_hash;
    let first = LedgerEntry::new(1, genesis_hash, b"issue_cert".to_vec(), 1_728_000_100_000);
    let second = LedgerEntry::new(
        2,
        first.block_hash,
        b"rotate_key".to_vec(),
        1_728_000_200_000,
    );
    let third = LedgerEntry::new(3, second.block_hash, b"revoke".to_vec(), 1_728_000_300_000);
    (ledger, vec![first, second, third])
}

pub fn valid_sequence() -> IntegrityCase {
    let (mut ledger, entries) = build_sequence();
    let mut sequence = Vec::new();
    for entry in entries {
        ledger.append(entry.clone()).expect("valid entry");
        sequence.push(entry);
    }
    IntegrityCase {
        description: "honest clients append sequential blocks",
        entries: sequence,
        expected_error: None,
    }
}

pub fn payload_tampering() -> IntegrityCase {
    let (_ledger, entries) = build_sequence();
    let mut tampered = entries[1].clone();
    tampered.payload.push(0xFF);
    let expected = payload_digest(&tampered.payload);
    // keep previous payload hash to trigger mismatch
    tampered.payload_hash = payload_digest(b"rotate_key");
    let found = tampered.payload_hash;
    IntegrityCase {
        description: "payload tampering detected via hash mismatch",
        entries: vec![entries[0].clone(), tampered],
        expected_error: Some(LedgerError::PayloadHashMismatch { expected, found }),
    }
}

pub fn stale_prev_hash() -> IntegrityCase {
    let (_ledger, entries) = build_sequence();
    let mut invalid = entries[2].clone();
    invalid.prev_hash = [0_u8; 32];
    IntegrityCase {
        description: "stale prev hash rejected",
        entries: vec![entries[0].clone(), entries[1].clone(), invalid],
        expected_error: Some(LedgerError::PrevHashMismatch {
            expected: entries[1].block_hash,
            found: [0_u8; 32],
        }),
    }
}

pub fn non_sequential_index() -> IntegrityCase {
    let (_ledger, entries) = build_sequence();
    let mut invalid = entries[1].clone();
    invalid.index = 7;
    IntegrityCase {
        description: "non sequential index rejected",
        entries: vec![entries[0].clone(), invalid],
        expected_error: Some(LedgerError::NonSequentialIndex {
            expected: 2,
            found: 7,
        }),
    }
}
