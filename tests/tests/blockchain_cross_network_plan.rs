#[path = "../blockchain/cross_network.rs"]
mod cross_network;

use cross_network::{
    cross_network_matrix, dataset_catalog, network_catalog, BridgingModel, LedgerStack,
};

fn finality_target(id: &str) -> std::time::Duration {
    network_catalog()
        .iter()
        .find(|profile| profile.id == id)
        .expect("network id should exist")
        .finality_target
}

#[test]
fn bridging_models_have_expected_finality_relationships() {
    for scenario in cross_network_matrix() {
        let source_finality = finality_target(scenario.source_network);
        let target_finality = finality_target(scenario.target_network);
        match scenario.bridging_model {
            BridgingModel::HashLockedWithMpc => {
                assert!(
                    target_finality >= source_finality,
                    "hash lock bridge requires slower or equal finality on target"
                );
            }
            BridgingModel::RateLimitedLightClient => {
                assert!(
                    target_finality > source_finality,
                    "light client bridge must settle to a slower L1 for replay buffering"
                );
            }
        }
    }
}

#[test]
fn dataset_controls_align_with_network_stacks() {
    let datasets = dataset_catalog();
    for scenario in cross_network_matrix() {
        let dataset = datasets
            .iter()
            .find(|candidate| candidate.id == scenario.dataset)
            .expect("dataset referenced by scenario");
        match (
            scenario.source_network,
            scenario.target_network,
            scenario.bridging_model,
        ) {
            ("fabric-devnet", "quorum-istanbul", BridgingModel::HashLockedWithMpc) => {
                assert!(
                    dataset.required_fields.contains(&"controls"),
                    "fabric→quorum bridge requires explicit control annotations"
                );
            }
            ("quorum-istanbul", "ethereum-sepolia", BridgingModel::RateLimitedLightClient) => {
                assert!(
                    dataset.required_fields.contains(&"controls"),
                    "quorum→sepolia bridge must include control evidence"
                );
            }
            _ => unreachable!("unexpected scenario definition"),
        }
    }
}

#[test]
fn stacks_cover_expected_ledgers() {
    let stacks: Vec<LedgerStack> = network_catalog()
        .iter()
        .map(|profile| profile.stack)
        .collect();
    assert!(stacks.contains(&LedgerStack::HyperledgerFabric));
    assert!(stacks.contains(&LedgerStack::QuorumIstanbul));
    assert!(stacks.contains(&LedgerStack::EthereumSepolia));
}
