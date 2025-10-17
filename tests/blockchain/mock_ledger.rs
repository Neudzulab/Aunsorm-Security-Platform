use sha2::{Digest, Sha256};

/// Calculates the SHA-256 digest of the provided payload.
pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let output = hasher.finalize();
    output.into()
}

fn block_digest(
    index: u64,
    prev_hash: &[u8; 32],
    payload_hash: &[u8; 32],
    timestamp_ms: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(prev_hash);
    hasher.update(payload_hash);
    hasher.update(timestamp_ms.to_be_bytes());
    let output = hasher.finalize();
    output.into()
}

/// Deterministic block representation used by the mock ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub index: u64,
    pub prev_hash: [u8; 32],
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub block_hash: [u8; 32],
}

impl LedgerEntry {
    /// Builds a new entry by hashing the payload deterministically.
    #[must_use]
    pub fn new(index: u64, prev_hash: [u8; 32], payload: Vec<u8>, timestamp_ms: u64) -> Self {
        let payload_hash = payload_digest(&payload);
        let block_hash = block_digest(index, &prev_hash, &payload_hash, timestamp_ms);
        Self {
            index,
            prev_hash,
            payload,
            payload_hash,
            timestamp_ms,
            block_hash,
        }
    }

    /// Returns the expected block hash computed from the public fields.
    #[must_use]
    pub fn recompute_block_hash(&self) -> [u8; 32] {
        block_digest(
            self.index,
            &self.prev_hash,
            &self.payload_hash,
            self.timestamp_ms,
        )
    }
}

/// Error conditions that indicate blockchain integrity violations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    NonSequentialIndex { expected: u64, found: u64 },
    PrevHashMismatch { expected: [u8; 32], found: [u8; 32] },
    PayloadHashMismatch { expected: [u8; 32], found: [u8; 32] },
    BlockHashMismatch { expected: [u8; 32], found: [u8; 32] },
}

/// Minimal trait describing a ledger backend that accepts sequential blocks.
pub trait LedgerBackend {
    fn append(&mut self, entry: LedgerEntry) -> Result<(), LedgerError>;
    fn latest(&self) -> &LedgerEntry;
    fn get(&self, index: u64) -> Option<&LedgerEntry>;
    fn len(&self) -> usize;
}

/// In-memory deterministic ledger used for regression testing.
pub struct InMemoryLedger {
    entries: Vec<LedgerEntry>,
}

impl InMemoryLedger {
    /// Creates a new ledger with a deterministic genesis block.
    #[must_use]
    pub fn bootstrap(genesis_payload: &[u8], timestamp_ms: u64) -> Self {
        let prev_hash = [0_u8; 32];
        let genesis = LedgerEntry::new(0, prev_hash, genesis_payload.to_vec(), timestamp_ms);
        Self {
            entries: vec![genesis],
        }
    }

    fn expected_next_index(&self) -> u64 {
        self.entries.last().map_or(0, |last| last.index + 1)
    }

    fn expected_prev_hash(&self) -> [u8; 32] {
        self.entries
            .last()
            .map_or([0_u8; 32], |last| last.block_hash)
    }
}

impl LedgerBackend for InMemoryLedger {
    fn append(&mut self, entry: LedgerEntry) -> Result<(), LedgerError> {
        let expected_index = self.expected_next_index();
        if entry.index != expected_index {
            return Err(LedgerError::NonSequentialIndex {
                expected: expected_index,
                found: entry.index,
            });
        }

        let expected_prev_hash = self.expected_prev_hash();
        if entry.prev_hash != expected_prev_hash {
            return Err(LedgerError::PrevHashMismatch {
                expected: expected_prev_hash,
                found: entry.prev_hash,
            });
        }

        let recalculated_payload = payload_digest(&entry.payload);
        if entry.payload_hash != recalculated_payload {
            return Err(LedgerError::PayloadHashMismatch {
                expected: recalculated_payload,
                found: entry.payload_hash,
            });
        }

        let recalculated_block = entry.recompute_block_hash();
        if entry.block_hash != recalculated_block {
            return Err(LedgerError::BlockHashMismatch {
                expected: recalculated_block,
                found: entry.block_hash,
            });
        }

        self.entries.push(entry);
        Ok(())
    }

    fn latest(&self) -> &LedgerEntry {
        self.entries
            .last()
            .expect("ledger always contains genesis entry")
    }

    fn get(&self, index: u64) -> Option<&LedgerEntry> {
        self.entries.iter().find(|entry| entry.index == index)
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}
