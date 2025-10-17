#![allow(clippy::too_many_lines)]

#[path = "../blockchain/integrity_cases.rs"]
mod integrity_cases;
#[path = "../blockchain/mock_ledger.rs"]
mod mock_ledger;

use integrity_cases::{
    non_sequential_index, payload_tampering, stale_prev_hash, valid_sequence, IntegrityCase,
};
use mock_ledger::{InMemoryLedger, LedgerBackend, LedgerError};

const GENESIS_TIMESTAMP: u64 = 1_728_000_000_000;

fn execute_case(case: &IntegrityCase) -> (InMemoryLedger, Option<LedgerError>) {
    let mut ledger = InMemoryLedger::bootstrap(b"genesis", GENESIS_TIMESTAMP);
    let mut failure = None;
    for entry in &case.entries {
        match ledger.append(entry.clone()) {
            Ok(()) => {}
            Err(err) => {
                failure = Some(err);
                break;
            }
        }
    }
    (ledger, failure)
}

#[test]
fn ledger_commits_valid_sequence_and_updates_head() {
    let case = valid_sequence();
    let expected_entries = case.entries.clone();
    let (ledger, failure) = execute_case(&case);
    assert!(failure.is_none(), "{}", case.description);
    assert_eq!(ledger.len(), expected_entries.len() + 1);
    let head = ledger.latest();
    let last = expected_entries.last().expect("sequence has entries");
    assert_eq!(head.block_hash, last.block_hash);
    assert_eq!(head.index, last.index);
    let retrieved = ledger
        .get(last.index)
        .expect("last block should be accessible by index");
    assert_eq!(retrieved.block_hash, head.block_hash);
}

#[test]
fn tampered_payload_is_rejected() {
    let case = payload_tampering();
    let (ledger, failure) = execute_case(&case);
    assert_eq!(ledger.len(), 2); // genesis + first honest block
    assert_eq!(failure, case.expected_error);
}

#[test]
fn stale_prev_hash_is_detected() {
    let case = stale_prev_hash();
    let (ledger, failure) = execute_case(&case);
    assert_eq!(ledger.len(), 3); // genesis + first two honest blocks
    assert_eq!(failure, case.expected_error);
}

#[test]
fn non_sequential_indices_are_rejected() {
    let case = non_sequential_index();
    let (ledger, failure) = execute_case(&case);
    assert_eq!(ledger.len(), 2); // genesis + first honest block
    assert_eq!(failure, case.expected_error);
}
