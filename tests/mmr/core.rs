use std::sync::Arc;

use accumulators::{
    hasher::{
        Hasher, keccak::KeccakHasher, stark_pedersen::StarkPedersenHasher,
        stark_poseidon::StarkPoseidonHasher,
    },
    mmr::{AppendResult, MMR, PeaksOptions, Proof, ProofOptions},
    store::{SubKey, memory::InMemoryStore, sqlite::SQLiteStore},
};

const LEAVES: [&str; 5] = ["1", "2", "3", "4", "5"];
async fn setup() -> (
    (MMR, Vec<AppendResult>),
    (MMR, Vec<AppendResult>),
    (MMR, Vec<AppendResult>),
) {
    let store = InMemoryStore::default();
    let poseidon_hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let keccak_hasher = Arc::new(KeccakHasher::new());
    let pedersen_hasher = Arc::new(StarkPedersenHasher::new());
    let mut append_result_pedersen: Vec<AppendResult> = vec![];
    let mut append_result_keccak: Vec<AppendResult> = vec![];
    let mut append_result_poseidon: Vec<AppendResult> = vec![];

    let store = Arc::new(store);

    let mut poseidon_mmr = MMR::new(store.clone(), poseidon_hasher.clone(), None);
    let mut keccak_mmr = MMR::new(store.clone(), keccak_hasher.clone(), None);
    let mut pedersen_mmr = MMR::new(store.clone(), pedersen_hasher.clone(), None);

    for leaf in LEAVES {
        append_result_poseidon.push(poseidon_mmr.append(leaf.to_string()).await.unwrap());
        append_result_keccak.push(keccak_mmr.append(leaf.to_string()).await.unwrap());
        append_result_pedersen.push(pedersen_mmr.append(leaf.to_string()).await.unwrap());
    }

    (
        (poseidon_mmr, append_result_poseidon),
        (keccak_mmr, append_result_keccak),
        (pedersen_mmr, append_result_pedersen),
    )
}

//================================================================================================
// Tests for append
//================================================================================================

#[tokio::test]
async fn should_compute_parent_tree_for_pedersen_hasher() {
    let pedersen_init = setup().await.2;

    let last_leaf_element_index = pedersen_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(StarkPedersenHasher::new());
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut pedersen_mmr = pedersen_init.0;

    assert_eq!(
        pedersen_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        pedersen_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(pedersen_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = pedersen_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(
        pedersen_mmr
            .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn should_compute_parent_tree_for_poseidon_hasher() {
    let poseidon_init = setup().await.0;

    let last_leaf_element_index = poseidon_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(StarkPoseidonHasher::new(None));
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut poseidon_mmr = poseidon_init.0;

    assert_eq!(
        poseidon_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        poseidon_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(poseidon_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = poseidon_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(
        poseidon_mmr
            .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn should_compute_parent_tree_for_keccak_hasher() {
    let keccak_init = setup().await.1;

    let last_leaf_element_index = keccak_init.1.last().unwrap().element_index;
    let appended_leaf = "6".to_string();

    let hasher = Arc::new(KeccakHasher::new());
    let node3 = hasher
        .hash(vec![LEAVES[0].to_string(), LEAVES[1].to_string()])
        .unwrap();
    let node6 = hasher
        .hash(vec![LEAVES[2].to_string(), LEAVES[3].to_string()])
        .unwrap();
    let node7 = hasher.hash(vec![node3, node6]).unwrap();
    let node10 = hasher
        .hash(vec![LEAVES[4].to_string(), appended_leaf.clone()])
        .unwrap();
    let bag = hasher.hash(vec![node7.clone(), node10.clone()]).unwrap();
    let root = hasher.hash(vec!["10".to_string(), bag.clone()]).unwrap();
    let mut keccak_mmr = keccak_init.0;

    assert_eq!(
        keccak_mmr.append(appended_leaf).await.unwrap(),
        AppendResult {
            element_index: 9,
            leaves_count: 6,
            elements_count: 10,
            root_hash: root,
        }
    );
    assert_eq!(
        keccak_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![node7, node10]
    );
    assert_eq!(keccak_mmr.bag_the_peaks(None).await.unwrap(), bag);
    let proof = keccak_mmr
        .get_proof(last_leaf_element_index, None)
        .await
        .unwrap();
    assert!(
        keccak_mmr
            .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
            .await
            .unwrap()
    );
}

//================================================================================================
// Tests for get and verify proof
//================================================================================================

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_pedersen_hasher() {
    let (pedersen_mmr, appends_results_for_pedersen) = setup().await.2;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_pedersen {
        let pedersen_mmr_clone = &pedersen_mmr;

        let proof = pedersen_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            pedersen_mmr
                .verify_proof(
                    proof.clone(),
                    LEAVES[idx].to_string(),
                    Some(ProofOptions {
                        elements_count: Some(proof.elements_count),
                        formatting_opts: None,
                    })
                )
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_keccak_hasher() {
    let (keccak_mmr, appends_results_for_keccak) = setup().await.1;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_keccak {
        let keccak_mmr_clone = &keccak_mmr;

        let proof = keccak_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            keccak_mmr
                .verify_proof(
                    proof.clone(),
                    LEAVES[idx].to_string(),
                    Some(ProofOptions {
                        elements_count: Some(proof.elements_count),
                        formatting_opts: None,
                    })
                )
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn should_generate_and_verify_non_expiring_proof_for_poseidon_hasher() {
    let (poseidon_mmr, appends_results_for_poseidon) = setup().await.0;
    let mut proofs: Vec<Proof> = vec![];
    for result in appends_results_for_poseidon {
        let poseidon_mmr_clone = &poseidon_mmr;

        let proof = poseidon_mmr_clone
            .get_proof(
                result.element_index,
                Some(ProofOptions {
                    elements_count: Some(result.elements_count),
                    formatting_opts: None,
                }),
            )
            .await
            .unwrap();

        proofs.push(proof);
    }

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            poseidon_mmr
                .verify_proof(
                    proof.clone(),
                    LEAVES[idx].to_string(),
                    Some(ProofOptions {
                        elements_count: Some(proof.elements_count),
                        formatting_opts: None,
                    })
                )
                .await
                .unwrap()
        );
    }
}

//================================================================================================
// Tests for get and verify multiple proofs
//================================================================================================

#[tokio::test]
async fn should_generate_multiple_proofs_for_pedersen_hasher() {
    let (pedersen_mmr, appends_results_for_pedersen) = setup().await.2;

    let element_indexes: Vec<_> = appends_results_for_pedersen
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = pedersen_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            pedersen_mmr
                .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn should_generate_multiple_proofs_for_keccak_hasher() {
    let (keccak_mmr, appends_results_for_keccak) = setup().await.1;

    let element_indexes: Vec<_> = appends_results_for_keccak
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = keccak_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            keccak_mmr
                .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn should_generate_multiple_proofs_for_poseidon_hasher() {
    let (poseidon_mmr, appends_results_for_poseidon) = setup().await.0;

    let element_indexes: Vec<_> = appends_results_for_poseidon
        .iter()
        .map(|r| r.element_index)
        .collect();

    let proofs = poseidon_mmr
        .get_proofs(element_indexes, None)
        .await
        .expect("Failed to get proofs");

    for (idx, proof) in proofs.iter().enumerate() {
        assert!(
            poseidon_mmr
                .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn test_get_peaks() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    mmr.append("1".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(peaks, vec!["1".to_string()]);

    mmr.append("2".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(
        peaks,
        vec![hasher.hash(vec!["1".to_string(), "2".to_string()]).unwrap()]
    );

    mmr.append("3".to_string()).await.unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(
        peaks,
        vec![
            hasher.hash(vec!["1".to_string(), "2".to_string()]).unwrap(),
            "3".to_string()
        ]
    );
}

/// Appends the golden leaf sequence ("1", "2", "4", "5", "8") to a fresh
/// poseidon MMR, asserting every intermediate `AppendResult` and bagged-peaks
/// value against known-good hashes.
async fn append_golden_leaves_to_poseidon_mmr(mmr: &mut MMR) {
    let append_result1 = mmr.append("1".to_string()).await.unwrap();

    assert_eq!(
        append_result1,
        AppendResult {
            element_index: 1,
            leaves_count: 1,
            elements_count: 1,
            root_hash: "0xb2b24ff607f861b3ed0a9868eeef700b7607ac6d71664afdd14a1f4c33f97d"
                .to_string(),
        }
    );

    assert_eq!(mmr.bag_the_peaks(None).await.unwrap(), "1");

    let append_result2 = mmr.append("2".to_string()).await.unwrap();

    assert_eq!(
        append_result2,
        AppendResult {
            element_index: 2,
            leaves_count: 2,
            elements_count: 3,
            root_hash: "0x97e6c17ea05508f6aef7a8195dee3da638bc44d22cbfff3a1f4d9ad215eb6d"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a"
    );

    let append_result4 = mmr.append("4".to_string()).await.unwrap();
    assert_eq!(
        append_result4,
        AppendResult {
            element_index: 4,
            leaves_count: 3,
            elements_count: 4,
            root_hash: "0x5caaf1cd5b1cf12d50730bb1e0c8a00ef696332a9019a4c7668deb11060620e"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x6f31a64a67c46b553960ae6b72bcf9fa3ccc6a4d6344e3799412e2c73a059b2"
    );
    let append_result5 = mmr.append("5".to_string()).await.unwrap();
    assert_eq!(
        append_result5,
        AppendResult {
            element_index: 5,
            leaves_count: 4,
            elements_count: 7,
            root_hash: "0x173b5ce39844d1534c8f545a3102fc28947f17ac3e16850413173291eb3e41b"
                .to_string(),
        }
    );
    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f"
    );
    let append_result8 = mmr.append("8".to_string()).await.unwrap();
    assert_eq!(
        append_result8,
        AppendResult {
            element_index: 8,
            leaves_count: 5,
            elements_count: 8,
            root_hash: "0x69c66f988b4b7942b56d9bebebdb0d6cf33f800e272ebf3cc7bd47d4f0d8641"
                .to_string(),
        }
    );

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x49da356656c3153d59f9be39143daebfc12e05b6a93ab4ccfa866a890ad78f"
    );
}

#[tokio::test]
async fn should_append_to_poseidon_mmr() {
    let store = Arc::new(InMemoryStore::default());
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let mut mmr = MMR::new(store, hasher, None);

    append_golden_leaves_to_poseidon_mmr(&mut mmr).await;

    assert_eq!(
        mmr.bag_the_peaks(None).await.unwrap(),
        "0x49da356656c3153d59f9be39143daebfc12e05b6a93ab4ccfa866a890ad78f"
    );
}

/// Gets the proof for an element, asserts its exact shape and verifies it
/// against the golden 5-leaf poseidon MMR state.
async fn get_and_verify_poseidon_proof(
    mmr: &mut MMR,
    element_index: usize,
    element_hash: &str,
    sibling_hash: &str,
    deep_sibling_hash: &str,
) {
    let proof = mmr.get_proof(element_index, None).await.unwrap();

    assert_eq!(
        proof,
        Proof {
            element_index,
            element_hash: element_hash.to_string(),
            siblings_hashes: vec![sibling_hash.to_string(), deep_sibling_hash.to_string()],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof, element_hash.to_string(), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn should_generate_and_verify_proofs_for_poseidon_mmr() {
    let store = Arc::new(InMemoryStore::default());
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let mut mmr = MMR::new(store, hasher, None);

    append_golden_leaves_to_poseidon_mmr(&mut mmr).await;

    get_and_verify_poseidon_proof(
        &mut mmr,
        1,
        "1",
        "2",
        "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4",
    )
    .await;
    get_and_verify_poseidon_proof(
        &mut mmr,
        2,
        "2",
        "1",
        "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4",
    )
    .await;
    get_and_verify_poseidon_proof(
        &mut mmr,
        4,
        "4",
        "5",
        "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a",
    )
    .await;
    get_and_verify_poseidon_proof(
        &mut mmr,
        5,
        "5",
        "4",
        "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a",
    )
    .await;
}

#[tokio::test]
async fn should_append_duplicate_to_mmr() {
    let store = SQLiteStore::new(":memory:", None, Some("test"))
        .await
        .unwrap();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store, hasher, None);
    let _ = mmr.append("4".to_string()).await;
    let _ = mmr.append("4".to_string()).await;

    let _root = mmr.bag_the_peaks(None).await.unwrap();
}

#[tokio::test]
async fn test_append_for_mmr() {
    let store = InMemoryStore::default();
    let store_rc = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::new(store_rc, hasher, None);

    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");
    mmr.append("3".to_string()).await.expect("Failed to append");
    let example_value = "4".to_string();
    let example_append = mmr
        .append(example_value.clone())
        .await
        .expect("Failed to append");

    let proof = mmr
        .get_proof(example_append.element_index, None)
        .await
        .expect("Failed to get proof");

    assert!(
        mmr.verify_proof(proof, example_value, None)
            .await
            .expect("Failed to verify proof")
    );
}

//================================================================================================
// Tests for create_with_genesis
//================================================================================================

#[tokio::test]
async fn test_create_with_genesis_for_keccak() {
    // Arrange
    let store = InMemoryStore::default();
    let hasher = Arc::new(KeccakHasher::new());
    let store = Arc::new(store);

    // Act
    let core_mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(
        core_mmr
            .root_hash
            .get(&SubKey::None)
            .await
            .unwrap()
            .unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis().unwrap()])
            .unwrap()
    );
}

#[tokio::test]
async fn test_create_with_genesis_for_poseidon() {
    // Arrange
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    // Act
    let core_mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(
        core_mmr
            .root_hash
            .get(&SubKey::None)
            .await
            .unwrap()
            .unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis().unwrap()])
            .unwrap()
    );
}

//================================================================================================
// Tests for get root hash from createWithGenesis with mix of hex and non-hex values
//================================================================================================

#[tokio::test]
async fn should_get_a_stable_root_hash_for_given_args_keccak_hasher() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(KeccakHasher::new());
    let store = Arc::new(store);

    let mut mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(mmr.leaves_count.get().await.unwrap(), 1);

    mmr.append("1".to_string()).await.unwrap();
    mmr.append("0x1".to_string()).await.unwrap();
    mmr.append("2".to_string()).await.unwrap();
    mmr.append("0x2".to_string()).await.unwrap();
    mmr.append("3".to_string()).await.unwrap();
    mmr.append("0x3".to_string()).await.unwrap();

    let stable_bag = "0x46d676ef5c3e8c6668ec577baee408f7b149d05b3ea31f4f2ad0d2a0ddc2a9b3";

    let element_count = mmr.leaves_count.get().await.unwrap();

    assert_eq!(element_count, 7);
    let bag = mmr.bag_the_peaks(None).await.unwrap();

    assert_eq!(&bag, stable_bag);

    let element_count = mmr.leaves_count.get().await.unwrap();

    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();

    let stable_root_hash = "0xe336600238639f1ea4e2d78db1c8353a896487fa8fb9f2c3898888817008b77b";

    assert_eq!(stable_root_hash, root_hash);
}

#[tokio::test]
async fn should_get_a_stable_root_hash_for_given_args_poseidon_hasher() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    let mut mmr = MMR::create_with_genesis(store, hasher.clone(), None)
        .await
        .unwrap();

    assert_eq!(mmr.leaves_count.get().await.unwrap(), 1);

    mmr.append("1".to_string()).await.unwrap();
    mmr.append("0x1".to_string()).await.unwrap();
    mmr.append("2".to_string()).await.unwrap();
    mmr.append("0x2".to_string()).await.unwrap();
    mmr.append("3".to_string()).await.unwrap();
    mmr.append("0x3".to_string()).await.unwrap();

    let stable_bag = "0x1b6fe636cf8f005b539f3d5c9ca5b5f435e995ecf51894fd3045a5e8389d467";

    let element_count = mmr.leaves_count.get().await.unwrap();

    assert_eq!(element_count, 7);
    let bag = mmr.bag_the_peaks(None).await.unwrap();

    assert_eq!(&bag, stable_bag);

    let element_count = mmr.leaves_count.get().await.unwrap();

    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();

    let stable_root_hash = "0x113e2abc1e91aa48aa7c12940061c924437fcd27829b8594de54a0cea57d232";

    assert_eq!(stable_root_hash, root_hash);
}

#[tokio::test]
async fn timestamp_remappers_test() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let store = Arc::new(store);

    let mut mmr = MMR::new(store, hasher.clone(), None);

    mmr.append("1715180160".to_string()).await.unwrap();
    mmr.append("1715180172".to_string()).await.unwrap();

    let element_count = mmr.elements_count.get().await.unwrap();
    println!("element_count: {element_count}");
    let bag = mmr.bag_the_peaks(Some(element_count)).await.unwrap();
    println!("bag: {bag}");
    let root_hash = mmr.calculate_root_hash(&bag, element_count).unwrap();
    println!("root_hash: {root_hash}");

    let correct_root_hash = "0x32f5a2949cac3d06e854701c5a2a00ed51c0475a31c1bc17cc6d3ec46425e9";
    assert_eq!(correct_root_hash, root_hash);
}

//================================================================================================
// Tests for create_from_peaks
//================================================================================================

async fn test_create_from_peaks_scenario(hasher: Arc<dyn Hasher>, mmr_id_prefix: &str) {
    // --- 1. Setup: Create a standard MMR and populate it ---
    let store1 = Arc::new(InMemoryStore::default());
    let mmr_id_orig = format!("{mmr_id_prefix}_orig");
    let mut original_mmr = MMR::new(store1.clone(), hasher.clone(), Some(mmr_id_orig.clone()));

    let mut original_appends = Vec::new();
    for leaf in LEAVES {
        original_appends.push(original_mmr.append(leaf.to_string()).await.unwrap());
    }

    let original_elements_count = original_mmr.elements_count.get().await.unwrap();
    let original_leaves_count = original_mmr.leaves_count.get().await.unwrap();
    let original_peaks = original_mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let original_bag = original_mmr.bag_the_peaks(None).await.unwrap();
    let original_root = original_mmr
        .root_hash
        .get(&SubKey::None)
        .await
        .unwrap()
        .unwrap(); // Assuming it's set

    // --- 2 & 3. Create MMR from Peaks and compare the initial state ---
    let mut from_peaks_mmr = create_from_peaks_and_assert_initial_state(
        hasher.clone(),
        mmr_id_prefix,
        original_elements_count,
        original_leaves_count,
        &original_peaks,
        &original_bag,
        &original_root,
    )
    .await;

    // --- 4. Append Comparison ---
    let (new_appends_orig, new_appends_peaks) =
        append_to_both_and_assert_final_state(&mut original_mmr, &mut from_peaks_mmr).await;

    // --- 5. Proof Comparison (New Values) ---
    assert_proofs_for_new_elements(
        &mut original_mmr,
        &mut from_peaks_mmr,
        &new_appends_orig,
        &new_appends_peaks,
    )
    .await;

    // --- 6. Proof Comparison (Old Values) ---
    assert_old_element_proof_behavior(
        &mut original_mmr,
        &mut from_peaks_mmr,
        original_appends[0].element_index,
        LEAVES[0],
    )
    .await;

    // --- 7. Additional Tests ---
    assert_create_from_peaks_error_cases(
        hasher.clone(),
        store1,
        mmr_id_prefix,
        &original_peaks,
        original_elements_count,
    )
    .await;
    assert_create_from_peaks_zero_elements(hasher.clone(), mmr_id_prefix).await;
    assert_create_from_peaks_one_element(hasher, mmr_id_prefix).await;
}

/// Creates an MMR from the original peaks and asserts its initial state
/// (elements count, leaves count, peaks, bag and root hash) matches the
/// original MMR's state.
async fn create_from_peaks_and_assert_initial_state(
    hasher: Arc<dyn Hasher>,
    mmr_id_prefix: &str,
    original_elements_count: usize,
    original_leaves_count: usize,
    original_peaks: &[String],
    original_bag: &str,
    original_root: &str,
) -> MMR {
    let store = Arc::new(InMemoryStore::default()); // Use a separate store or MMR ID
    let mmr_id_peaks = format!("{mmr_id_prefix}_peaks");
    let from_peaks_mmr = MMR::create_from_peaks(
        store,
        hasher,
        Some(mmr_id_peaks),
        original_peaks.to_vec(),
        original_elements_count,
    )
    .await
    .unwrap();

    assert_eq!(
        from_peaks_mmr.elements_count.get().await.unwrap(),
        original_elements_count,
        "Initial elements_count mismatch"
    );
    assert_eq!(
        from_peaks_mmr.leaves_count.get().await.unwrap(),
        original_leaves_count,
        "Initial leaves_count mismatch"
    );
    assert_eq!(
        from_peaks_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        original_peaks,
        "Initial peaks mismatch"
    );
    assert_eq!(
        from_peaks_mmr.bag_the_peaks(None).await.unwrap(),
        original_bag,
        "Initial bag mismatch"
    );
    assert_eq!(
        from_peaks_mmr
            .root_hash
            .get(&SubKey::None)
            .await
            .unwrap()
            .unwrap(),
        original_root,
        "Initial root hash mismatch"
    );

    from_peaks_mmr
}

/// Appends new elements to both MMRs and asserts their final states
/// (elements count, leaves count, peaks, bag, root hash and append results)
/// match.
async fn append_to_both_and_assert_final_state(
    original_mmr: &mut MMR,
    from_peaks_mmr: &mut MMR,
) -> (Vec<AppendResult>, Vec<AppendResult>) {
    let new_elements = ["6", "7", "8"];
    let mut new_appends_orig = Vec::new();
    let mut new_appends_peaks = Vec::new();

    for &element in &new_elements {
        new_appends_orig.push(original_mmr.append(element.to_string()).await.unwrap());
        new_appends_peaks.push(from_peaks_mmr.append(element.to_string()).await.unwrap());
    }

    // Compare final state after appends
    let final_elements_count_orig = original_mmr.elements_count.get().await.unwrap();
    let final_leaves_count_orig = original_mmr.leaves_count.get().await.unwrap();
    let final_peaks_orig = original_mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let final_bag_orig = original_mmr.bag_the_peaks(None).await.unwrap();
    let final_root_orig = original_mmr
        .root_hash
        .get(&SubKey::None)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        from_peaks_mmr.elements_count.get().await.unwrap(),
        final_elements_count_orig,
        "Final elements_count mismatch"
    );
    assert_eq!(
        from_peaks_mmr.leaves_count.get().await.unwrap(),
        final_leaves_count_orig,
        "Final leaves_count mismatch"
    );
    assert_eq!(
        from_peaks_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        final_peaks_orig,
        "Final peaks mismatch"
    );
    assert_eq!(
        from_peaks_mmr.bag_the_peaks(None).await.unwrap(),
        final_bag_orig,
        "Final bag mismatch"
    );
    assert_eq!(
        from_peaks_mmr
            .root_hash
            .get(&SubKey::None)
            .await
            .unwrap()
            .unwrap(),
        final_root_orig,
        "Final root hash mismatch"
    );
    assert_eq!(
        new_appends_peaks, new_appends_orig,
        "AppendResults mismatch"
    );

    (new_appends_orig, new_appends_peaks)
}

/// Proofs for the newly appended elements must match between the two MMRs and
/// cross-verify in both directions.
async fn assert_proofs_for_new_elements(
    original_mmr: &mut MMR,
    from_peaks_mmr: &mut MMR,
    new_appends_orig: &[AppendResult],
    new_appends_peaks: &[AppendResult],
) {
    let new_elements = ["6", "7", "8"];
    for i in 0..new_elements.len() {
        let element_value = new_elements[i].to_string();
        let element_index_orig = new_appends_orig[i].element_index;
        let element_index_peaks = new_appends_peaks[i].element_index;

        assert_eq!(
            element_index_orig, element_index_peaks,
            "New element indices mismatch"
        );

        let proof_orig = original_mmr
            .get_proof(element_index_orig, None)
            .await
            .unwrap();
        let proof_peaks = from_peaks_mmr
            .get_proof(element_index_peaks, None)
            .await
            .unwrap();

        assert_eq!(
            proof_orig, proof_peaks,
            "Proofs for new element {element_value} mismatch"
        );

        assert!(
            original_mmr
                .verify_proof(proof_orig.clone(), element_value.clone(), None)
                .await
                .unwrap(),
            "Original MMR failed verifying new proof for {element_value}"
        );
        assert!(
            from_peaks_mmr
                .verify_proof(proof_peaks.clone(), element_value.clone(), None)
                .await
                .unwrap(),
            "FromPeaks MMR failed verifying new proof for {element_value}"
        );
        // Cross-verify
        assert!(
            original_mmr
                .verify_proof(proof_peaks.clone(), element_value.clone(), None)
                .await
                .unwrap(),
            "Original MMR failed verifying FromPeaks new proof for {element_value}"
        );
        assert!(
            from_peaks_mmr
                .verify_proof(proof_orig.clone(), element_value.clone(), None)
                .await
                .unwrap(),
            "FromPeaks MMR failed verifying Original new proof for {element_value}"
        );
    }
}

/// A proof from the original MMR for an element appended before the
/// `create_from_peaks` snapshot must still verify, while a proof generated by
/// the from-peaks MMR for such an element must NOT verify: intermediate hashes
/// below the initial peaks are missing. If `get_proof` itself errors, that is
/// acceptable too.
async fn assert_old_element_proof_behavior(
    original_mmr: &mut MMR,
    from_peaks_mmr: &mut MMR,
    old_element_index: usize,
    old_element_value: &str,
) {
    // Proof from original MMR should work
    let proof_orig_old = original_mmr
        .get_proof(old_element_index, None)
        .await
        .unwrap();
    assert!(
        original_mmr
            .verify_proof(proof_orig_old, old_element_value.to_string(), None)
            .await
            .unwrap(),
        "Original MMR failed verifying old proof"
    );

    let proof_peaks_old_res = from_peaks_mmr.get_proof(old_element_index, None).await;

    if let Ok(proof_peaks_old) = proof_peaks_old_res {
        assert!(
            !from_peaks_mmr
                .verify_proof(proof_peaks_old, old_element_value.to_string(), None)
                .await
                .unwrap_or(false), // Expect verify to fail
            "FromPeaks MMR incorrectly verified proof for an element below initial peaks"
        );
    }
}

/// `create_from_peaks` must fail with `InvalidPeaksCountForElements` for a
/// wrong peaks count and with `NonEmptyMMR` when reusing an existing MMR ID.
async fn assert_create_from_peaks_error_cases(
    hasher: Arc<dyn Hasher>,
    original_store: Arc<InMemoryStore>,
    mmr_id_prefix: &str,
    original_peaks: &[String],
    original_elements_count: usize,
) {
    // Test: Create from peaks with invalid peaks count
    let store = Arc::new(InMemoryStore::default());
    let mmr_id_err1 = format!("{mmr_id_prefix}_err1");
    let mut wrong_peaks = original_peaks.to_vec();
    wrong_peaks.pop(); // Make the count incorrect
    let err_res = MMR::create_from_peaks(
        store,
        hasher.clone(),
        Some(mmr_id_err1),
        wrong_peaks,
        original_elements_count,
    )
    .await;
    assert!(
        matches!(
            err_res,
            Err(accumulators::mmr::MMRError::InvalidPeaksCountForElements)
        ),
        "Expected InvalidPeaksCountForElements error"
    );

    // Test: Create from peaks on a non-empty MMR (using same ID as original)
    let err_res_non_empty = MMR::create_from_peaks(
        original_store, // Use the store where original_mmr exists
        hasher,
        Some(format!("{mmr_id_prefix}_orig")), // Use the same MMR ID
        original_peaks.to_vec(),
        original_elements_count,
    )
    .await;
    assert!(
        matches!(
            err_res_non_empty,
            Err(accumulators::mmr::MMRError::NonEmptyMMR)
        ),
        "Expected NonEmptyMMR error"
    );
}

/// `create_from_peaks` with 0 elements yields an empty MMR that behaves
/// consistently and can be appended to.
async fn assert_create_from_peaks_zero_elements(hasher: Arc<dyn Hasher>, mmr_id_prefix: &str) {
    let store = Arc::new(InMemoryStore::default());
    let mmr_id_zero = format!("{mmr_id_prefix}_zero");
    let mut zero_mmr = MMR::create_from_peaks(store, hasher, Some(mmr_id_zero), vec![], 0)
        .await
        .unwrap();
    assert_eq!(zero_mmr.elements_count.get().await.unwrap(), 0);
    assert_eq!(zero_mmr.leaves_count.get().await.unwrap(), 0);
    assert_eq!(
        zero_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap()
            .len(),
        0
    );
    let zero_bag = zero_mmr.bag_the_peaks(None).await.unwrap();
    let zero_root = zero_mmr
        .root_hash
        .get(&SubKey::None)
        .await
        .unwrap()
        .unwrap();
    let expected_zero_root = zero_mmr.calculate_root_hash(&zero_bag, 0).unwrap();
    assert_eq!(zero_root, expected_zero_root);
    // Append to zero MMR and check
    let append_res_zero = zero_mmr.append("1000".to_string()).await.unwrap();
    assert_eq!(append_res_zero.elements_count, 1);
    assert_eq!(append_res_zero.leaves_count, 1);
}

/// `create_from_peaks` with 1 element yields a one-leaf MMR that bags to the
/// peak itself and can be appended to.
async fn assert_create_from_peaks_one_element(hasher: Arc<dyn Hasher>, mmr_id_prefix: &str) {
    let store = Arc::new(InMemoryStore::default());
    let mmr_id_one = format!("{mmr_id_prefix}_one");
    let single_element_hash = "0x1001".to_string(); // Use a simple string for test
    let mut one_mmr = MMR::create_from_peaks(
        store,
        hasher,
        Some(mmr_id_one),
        vec![single_element_hash.clone()],
        1, // elements_count = 1
    )
    .await
    .unwrap();
    assert_eq!(one_mmr.elements_count.get().await.unwrap(), 1);
    assert_eq!(one_mmr.leaves_count.get().await.unwrap(), 1);
    assert_eq!(
        one_mmr
            .get_peaks(PeaksOptions {
                elements_count: None,
                formatting_opts: None,
            })
            .await
            .unwrap(),
        vec![single_element_hash.clone()]
    );
    let one_bag = one_mmr.bag_the_peaks(None).await.unwrap();
    assert_eq!(one_bag, single_element_hash); // Bagging 1 peak is the peak itself
    let one_root = one_mmr.root_hash.get(&SubKey::None).await.unwrap().unwrap();
    let expected_one_root = one_mmr.calculate_root_hash(&one_bag, 1).unwrap();
    assert_eq!(one_root, expected_one_root);
    // Append and check
    let append_res_one = one_mmr.append("2000".to_string()).await.unwrap();
    assert_eq!(append_res_one.elements_count, 3); // 1 (leaf) + 1 (leaf) + 1 (parent)
    assert_eq!(append_res_one.leaves_count, 2);
}

#[tokio::test]
async fn test_create_from_peaks_poseidon() {
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    test_create_from_peaks_scenario(hasher, "poseidon_peaks_test").await;
}

#[tokio::test]
async fn test_create_from_peaks_keccak() {
    let hasher = Arc::new(KeccakHasher::new());
    test_create_from_peaks_scenario(hasher, "keccak_peaks_test").await;
}

#[tokio::test]
async fn test_create_from_peaks_pedersen() {
    let hasher = Arc::new(StarkPedersenHasher::new());
    test_create_from_peaks_scenario(hasher, "pedersen_peaks_test").await;
}
