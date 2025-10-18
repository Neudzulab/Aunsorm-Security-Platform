use std::time::Duration;

/// Supported blockchain stacks that participate in the interoperability plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LedgerStack {
    HyperledgerFabric,
    QuorumIstanbul,
    EthereumSepolia,
}

/// Bridge coordination models evaluated by the interoperability harness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BridgingModel {
    HashLockedWithMpc,
    RateLimitedLightClient,
}

/// Declarative profile describing each participating network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkProfile {
    pub id: &'static str,
    pub stack: LedgerStack,
    pub consensus: &'static str,
    pub finality_target: Duration,
    pub control_points: &'static [&'static str],
    pub compliance_refs: &'static [&'static str],
}

/// Dataset requirements for deterministic cross-network regression tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatasetRequirement {
    pub id: &'static str,
    pub fixture_path: &'static str,
    pub documentation_path: &'static str,
    pub record_hint: usize,
    pub required_fields: &'static [&'static str],
}

/// Planned scenarios tying networks, bridge model and dataset requirements together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossNetworkScenario {
    pub id: &'static str,
    pub source_network: &'static str,
    pub target_network: &'static str,
    pub bridging_model: BridgingModel,
    pub dataset: &'static str,
    pub invariants: &'static [&'static str],
}

const FABRIC_CONTROL_POINTS: [&str; 3] = [
    "chaincode_hash_lock",
    "channel_msp_dual_signature",
    "fabric_orderer_timestamp",
];

const QUORUM_CONTROL_POINTS: [&str; 3] = [
    "istanbul_bft_commit",
    "mpc_release_contract",
    "rate_limit_enforcer",
];

const SEPOLIA_CONTROL_POINTS: [&str; 3] = [
    "l1_finality_checkpoint",
    "proof_oracle_attestation",
    "travel_rule_export",
];

const FABRIC_COMPLIANCE: [&str; 2] = ["FATF-Travel-Rule", "ISO20022-Bridge-Ledger"];
const QUORUM_COMPLIANCE: [&str; 2] = ["FATF-Travel-Rule", "SOC2-CC6"];
const SEPOLIA_COMPLIANCE: [&str; 2] = ["FATF-Travel-Rule", "EU-MiCA-Draft"];

const FABRIC_TO_QUORUM_FIELDS: [&str; 11] = [
    "transfer_id",
    "fabric_channel",
    "fabric_block",
    "fabric_tx",
    "quorum_block",
    "quorum_tx",
    "asset",
    "amount",
    "kyc_reference",
    "controls",
    "timestamp_ms",
];

const QUORUM_TO_SEPOLIA_FIELDS: [&str; 10] = [
    "settlement_id",
    "quorum_block",
    "quorum_tx",
    "sepolia_block",
    "sepolia_tx",
    "asset",
    "amount",
    "aml_case_reference",
    "timestamp_ms",
    "controls",
];

const FABRIC_TO_QUORUM_INVARIANTS: [&str; 3] = [
    "msp_dual_signature_verified",
    "kyc_reference_carried_forward",
    "finality_delta_under_500ms",
];

const QUORUM_TO_SEPOLIA_INVARIANTS: [&str; 3] = [
    "rate_limit_window_enforced",
    "oracle_snapshot_consistent",
    "finality_less_than_five_blocks",
];

/// Returns the supported network profiles for the cross-network harness.
#[must_use]
pub fn network_catalog() -> &'static [NetworkProfile] {
    const NETWORKS: &[NetworkProfile; 3] = &[
        NetworkProfile {
            id: "fabric-devnet",
            stack: LedgerStack::HyperledgerFabric,
            consensus: "Raft + MSP channel policies",
            finality_target: Duration::from_millis(400),
            control_points: &FABRIC_CONTROL_POINTS,
            compliance_refs: &FABRIC_COMPLIANCE,
        },
        NetworkProfile {
            id: "quorum-istanbul",
            stack: LedgerStack::QuorumIstanbul,
            consensus: "IBFT 2.0",
            finality_target: Duration::from_secs(1),
            control_points: &QUORUM_CONTROL_POINTS,
            compliance_refs: &QUORUM_COMPLIANCE,
        },
        NetworkProfile {
            id: "ethereum-sepolia",
            stack: LedgerStack::EthereumSepolia,
            consensus: "PoS Finality Gadget",
            finality_target: Duration::from_secs(12),
            control_points: &SEPOLIA_CONTROL_POINTS,
            compliance_refs: &SEPOLIA_COMPLIANCE,
        },
    ];
    NETWORKS
}

/// Returns the dataset requirements along with their fixture locations.
#[must_use]
pub fn dataset_catalog() -> &'static [DatasetRequirement] {
    const DATASETS: &[DatasetRequirement; 2] = &[
        DatasetRequirement {
            id: "fabric-to-quorum-transfers-v1",
            fixture_path: "data/blockchain/fabric_to_quorum_transfers.json",
            documentation_path: "data/blockchain/fabric_to_quorum_transfers.md",
            record_hint: 2,
            required_fields: &FABRIC_TO_QUORUM_FIELDS,
        },
        DatasetRequirement {
            id: "quorum-to-sepolia-settlements-v1",
            fixture_path: "data/blockchain/quorum_to_sepolia_settlements.json",
            documentation_path: "data/blockchain/quorum_to_sepolia_settlements.md",
            record_hint: 2,
            required_fields: &QUORUM_TO_SEPOLIA_FIELDS,
        },
    ];
    DATASETS
}

/// Provides the interoperability scenarios that the harness must execute.
#[must_use]
pub fn cross_network_matrix() -> &'static [CrossNetworkScenario] {
    const SCENARIOS: &[CrossNetworkScenario; 2] = &[
        CrossNetworkScenario {
            id: "fabric-to-quorum-stablecoin",
            source_network: "fabric-devnet",
            target_network: "quorum-istanbul",
            bridging_model: BridgingModel::HashLockedWithMpc,
            dataset: "fabric-to-quorum-transfers-v1",
            invariants: &FABRIC_TO_QUORUM_INVARIANTS,
        },
        CrossNetworkScenario {
            id: "quorum-to-sepolia-settlement",
            source_network: "quorum-istanbul",
            target_network: "ethereum-sepolia",
            bridging_model: BridgingModel::RateLimitedLightClient,
            dataset: "quorum-to-sepolia-settlements-v1",
            invariants: &QUORUM_TO_SEPOLIA_INVARIANTS,
        },
    ];
    SCENARIOS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::fs;
    use std::path::Path;

    #[test]
    fn dataset_ids_are_unique_and_files_exist() {
        let datasets = dataset_catalog();
        let mut ids = HashSet::new();
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        for dataset in datasets {
            assert!(
                ids.insert(dataset.id),
                "duplicate dataset id: {}",
                dataset.id
            );
            let fixture_path = manifest_dir.join(dataset.fixture_path);
            assert!(
                fixture_path.exists(),
                "missing fixture: {}",
                dataset.fixture_path
            );
            let doc_path = manifest_dir.join(dataset.documentation_path);
            assert!(
                doc_path.exists(),
                "missing documentation: {}",
                dataset.documentation_path
            );
        }
    }

    #[test]
    fn scenarios_reference_known_networks_and_datasets() {
        let networks: HashSet<&str> = network_catalog().iter().map(|profile| profile.id).collect();
        let datasets: HashSet<&str> = dataset_catalog().iter().map(|dataset| dataset.id).collect();
        for scenario in cross_network_matrix() {
            assert!(networks.contains(scenario.source_network));
            assert!(networks.contains(scenario.target_network));
            assert!(datasets.contains(scenario.dataset));
            assert!(!scenario.invariants.is_empty());
        }
    }

    #[test]
    fn record_hints_match_fixture_lengths() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        for dataset in dataset_catalog() {
            let fixture_path = manifest_dir.join(dataset.fixture_path);
            let content = fs::read_to_string(&fixture_path)
                .unwrap_or_else(|err| panic!("failed to read {}: {err}", dataset.fixture_path));
            let parsed: serde_json::Value = serde_json::from_str(&content)
                .unwrap_or_else(|err| panic!("failed to parse {}: {err}", dataset.fixture_path));
            let Some(array) = parsed.as_array() else {
                panic!("fixture {} must contain a JSON array", dataset.fixture_path);
            };
            assert_eq!(array.len(), dataset.record_hint, "unexpected record count");
            for field in dataset.required_fields {
                let missing_index = array
                    .iter()
                    .enumerate()
                    .find_map(|(index, entry)| match entry.as_object() {
                        Some(object) if object.contains_key(*field) => None,
                        _ => Some(index),
                    });
                if let Some(index) = missing_index {
                    panic!(
                        "fixture {} missing field {} at index {}",
                        dataset.fixture_path, field, index
                    );
                }
            }
        }
    }
}
