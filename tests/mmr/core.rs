use std::sync::Arc;

use accumulators::{
    hasher::{
        keccak::KeccakHasher, stark_pedersen::StarkPedersenHasher,
        stark_poseidon::StarkPoseidonHasher, Hasher,
    },
    mmr::{AppendResult, PeaksOptions, Proof, ProofOptions, MMR},
    store::{memory::InMemoryStore, sqlite::SQLiteStore, SubKey},
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
    assert!(pedersen_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
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
    assert!(poseidon_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
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
    assert!(keccak_mmr
        .verify_proof(proof, LEAVES[LEAVES.len() - 1].to_string(), None)
        .await
        .unwrap())
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
        assert!(pedersen_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
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
        assert!(keccak_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
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
        assert!(poseidon_mmr
            .verify_proof(
                proof.clone(),
                LEAVES[idx].to_string(),
                Some(ProofOptions {
                    elements_count: Some(proof.elements_count),
                    formatting_opts: None,
                })
            )
            .await
            .unwrap());
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
        assert!(pedersen_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
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
        assert!(keccak_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
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
        assert!(poseidon_mmr
            .verify_proof(proof.clone(), LEAVES[idx].to_string(), None)
            .await
            .unwrap())
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

#[tokio::test]
async fn should_append_to_poseidon_mmr() {
    let store = InMemoryStore::default();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    // Act
    // let mut mmr = CoreMMR::create_with_genesis(store, hasher.clone(), None).unwrap();
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

    let proof1 = mmr.get_proof(1, None).await.unwrap();

    assert_eq!(
        proof1,
        Proof {
            element_index: 1,
            element_hash: "1".to_string(),
            siblings_hashes: vec![
                "2".to_string(),
                "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof1, "1".to_string(), None)
        .await
        .unwrap();

    let proof2 = mmr.get_proof(2, None).await.unwrap();

    assert_eq!(
        proof2,
        Proof {
            element_index: 2,
            element_hash: "2".to_string(),
            siblings_hashes: vec![
                "1".to_string(),
                "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof2, "2".to_string(), None)
        .await
        .unwrap();

    let proof4 = mmr.get_proof(4, None).await.unwrap();

    assert_eq!(
        proof4,
        Proof {
            element_index: 4,
            element_hash: "4".to_string(),
            siblings_hashes: vec![
                "5".to_string(),
                "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof4, "4".to_string(), None)
        .await
        .unwrap();

    let proof5 = mmr.get_proof(5, None).await.unwrap();

    assert_eq!(
        proof5,
        Proof {
            element_index: 5,
            element_hash: "5".to_string(),
            siblings_hashes: vec![
                "4".to_string(),
                "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a".to_string()
            ],
            peaks_hashes: vec![
                "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f".to_string(),
                "8".to_string()
            ],
            elements_count: 8
        }
    );

    mmr.verify_proof(proof5, "5".to_string(), None)
        .await
        .unwrap();
}

#[tokio::test]
async fn should_append_duplicate_to_mmr() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();
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

    assert!(mmr
        .verify_proof(proof, example_value, None)
        .await
        .expect("Failed to verify proof"));
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
        core_mmr.root_hash.get(SubKey::None).await.unwrap().unwrap(),
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
        core_mmr.root_hash.get(SubKey::None).await.unwrap().unwrap(),
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

//================================================================================================
// Tests from createWithGenesis for given block range
//================================================================================================

#[tokio::test]
async fn append_block_range_keccak_aggregator() {
    use accumulators::{mmr::MMR, store::memory::InMemoryStore};

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(KeccakHasher::new());

    let mut mmr = MMR::create_with_genesis(store.clone(), hasher.clone(), Some("mmr".to_string()))
        .await
        .unwrap();

    // block 9734438
    mmr.append("0xcd5631a363d4c9bfc86d3504102595c39d7cd90a940fd165e1bdd911aa504d0a".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        2,
        "leaves_count  should be 2"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        3,
        "elements_count  should be 3"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0xffbb02de013f6837d8e0da5f4215c53634c32a4f5eb2520f26a1d6d2f615db72"
    );

    // block 9734439
    mmr.append("0x62154309a502f33764c4ec3267e2cabf561dc9e428b0607f6f458942bbe0e02d".to_string())
        .await
        .expect("Failed to append");

    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        3,
        "leaves_count  should be 3"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        4,
        "elements_count  should be 4"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0xaeb642d0f47f806382c66494ccf42c7d37eb3e09ba507a3b842e2a080c745200"
    );

    // block 9734440
    mmr.append("0x5104aee2cb3cc519cca3580144624c197a0e8b80ef080fe29698221f9963207d".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        4,
        "leaves_count  should be 4"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        7,
        "elements_count  should be 7"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0xdae951c569985cea6033958972846338710ba372aef365053428d1eccfe5e5ce"
    );

    // block 9734441
    mmr.append("0x09ab9ad1513282a5c1e1b4c15436aee479e9759712ebe6e5dbb02411537633e1".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        5,
        "leaves_count  should be 5"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        8,
        "elements_count  should be 8"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0xd4675f556d04ea6828165e6ad778f3162978588890061692189a55002d93572a"
    );

    // block 9734442
    mmr.append("0x5cb8bb916e22e6ab4c0fca4bebc13b05dcaaa7eccacd7636b755d944de4e9217".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        6,
        "leaves_count  should be 6"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        10,
        "elements_count  should be 10"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    // TODO: TS-ACCUMULATOR is 0x70c01463d822d2205868c5a46eefc55658828015b83e4553c8462d2c6711d0e0
    assert_eq!(
        root,
        "0x1a0a347398081822baeed647ee46c1a50e406133341a0de3f33bb7805092d20d"
    );

    // block 9734443
    mmr.append("0x0b756461f355b8fb1a6dfdfe5d943f7c037c62b99e806a579500a8a73821e250".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        7,
        "leaves_count  should be 7"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        11,
        "elements_count  should be 11"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    // TODO: TS-ACCUMULATOR is 0x7d0011a4256839263340fb483eb9fe3f6ce8506c9cc39699d8c1a65d8f34257a
    assert_eq!(
        root,
        "0xca529894efcbddf50b068eccd23d451e081053bc9492d5f69db1164ed4f63b85"
    );

    // block 9734444
    mmr.append("0x3965b0ccf016b56564129ab0f96400c3a84a8e6fa5d25327a6a1762901ee00e9".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        8,
        "leaves_count  should be 8"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        15,
        "elements_count  should be 15"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    // TODO: TS-ACCUMULATOR is 0x961d2a731654c2d9027c787a9296c66f841d1ee4a13abfdf7a83b70fd7217060
    assert_eq!(
        root,
        "0x35671dfbd86539afa71aaf4a813550d18bfc36b1e91a5c88554e5b947de510a7"
    );

    // block 9734445
    mmr.append("0xbe9e359d2632091546be983f8b6488012d607d56c05599c9347fdfdbd86c1b3f".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        9,
        "leaves_count  should be 9"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        16,
        "elements_count  should be 16"
    );
    assert_eq!(
        mmr.root_hash.get(SubKey::None).await.unwrap().unwrap(),
        "0x27bb48900f6889477589097c26b821aaba4b709b8ea10a5a871ff59f161ea98c",
        "root_hash should be 0x4226038dc6fba77fa92ce5d63a49945266065914571c59ef85bdf184eee6dc36"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    // TODO: TS-ACCUMULATOR is 0x4226038dc6fba77fa92ce5d63a49945266065914571c59ef85bdf184eee6dc36
    assert_eq!(
        root,
        "0x27bb48900f6889477589097c26b821aaba4b709b8ea10a5a871ff59f161ea98c"
    );

    // block 9734446
    mmr.append("0xe9112c401620687b34b0fc6108f35242d32ff37914e302c423e9134851573f65".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        10,
        "leaves_count  should be 10"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        18,
        "elements_count  should be 18"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    // TODO: TS-ACCUMULATOR is 0xc5cce3ec5640e0165df5cf8aa5897eb7b9b54b6c4a17d13e0a007b12cfc223cd
    assert_eq!(
        root,
        "0xfa8d8951eb33ddd3fcc414328df9c0406bdb0f1de47d7302dd0e40b552d5af19"
    );

    // block 9734447
    mmr.append("0xd6b12b6b12b253be08a02293261f71383d6159b6339d6aeab45d91643df19bd0".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        11,
        "leaves_count  should be 11"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        19,
        "elements_count  should be 19"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0xc87c3ba0942e428ad5432078aa7bb0b9d423616a3a1c8c7fc27b546a81465aaf
    //TODO: TS-ACCUMULATOR is 0x4654b1a9b7311b0b896ada391a9481db2c0756d9c0f32658facff9eec32cd18b
    assert_eq!(
        root,
        "0x3833c0ee0a0f3b2d8fa8597c49eed0e53054463fc9ecf05150a188c85142050b"
    );
}

#[tokio::test]
async fn append_block_range_poseidon_aggregator() {
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
    };

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::create_with_genesis(store.clone(), hasher.clone(), Some("mmr".to_string()))
        .await
        .unwrap();

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(peaks, vec![hasher.get_genesis().unwrap()]);

    // block 9734438
    let node2 = "0x07b8996d5b585da92efa32a57223dfb28fa12e6c04d36d7edb03690f03bec56";
    mmr.append(node2.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        2,
        "leaves_count  should be 2"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        3,
        "elements_count  should be 3"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root, "0x1070995027591e1b97c73c0e59933ee1a4227781434dd94b2d4dc87fd94cf92",
        "root "
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    assert_eq!(
        peaks,
        vec![hasher
            .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
            .unwrap()]
    );

    // block 9734439
    let node3 = "0x312134454804550b4a38e1d60dc1f0be80ff62dfea8f3c6be0c257efce3b833";
    mmr.append(node3.to_string())
        .await
        .expect("Failed to append");

    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        3,
        "leaves_count  should be 3"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        4,
        "elements_count  should be 4"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x1a2be63d0560708d3eb87319be0442016ba8757557da8009096e95c4b0682d9"
    );
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
            hasher
                .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                .unwrap(),
            node3.to_string()
        ]
    );

    // block 9734440
    let node4 = "0x6f0b4ef760469262221de032372c2a6b47b304a48b632af80611fc2e2e10b56";
    mmr.append(node4.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        4,
        "leaves_count  should be 4"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        7,
        "elements_count  should be 7"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x1006c333b41230ee484977b481e0e4e530f454a6d14902ce593ed2dbf649a25"
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    let hash = hasher
        .hash(vec![
            hasher
                .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                .unwrap(),
            hasher
                .hash(vec![node3.to_string(), node4.to_string()])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(peaks, vec![hash]);

    // block 9734441
    let node5 = "0x7f6d47c24e8723a6d6cf4ef089df0bd3ec710d5448b696e47b037109a1d04ce";
    mmr.append(node5.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        5,
        "leaves_count  should be 5"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        8,
        "elements_count  should be 8"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x4f05ebf1a932fdc481d43eb577ad326e5a8c743fbc8624eb98010b65f8c5b89"
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();

    let hash = hasher
        .hash(vec![
            hasher
                .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                .unwrap(),
            hasher
                .hash(vec![node3.to_string(), node4.to_string()])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(peaks, vec![hash, node5.to_string()]);

    // block 9734442
    let node6 = "0x38e557fbc306cbcb5964a503014b375db68a0c6786fd9c6ffc5cdd14b6c9dfc";
    mmr.append(node6.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        6,
        "leaves_count  should be 6"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        10,
        "elements_count  should be 10"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x13bdeaf86b66a03cb316c62d475a7e8d037d30ee7b5d52ff1b13f2fb951b527"
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let hash = hasher
        .hash(vec![
            hasher
                .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                .unwrap(),
            hasher
                .hash(vec![node3.to_string(), node4.to_string()])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(
        peaks,
        vec![
            hash,
            hasher
                .hash(vec![node5.to_string(), node6.to_string()])
                .unwrap()
        ]
    );

    // block 9734443
    let node7 = "0x54aa6067e8c4f6bcd7c47cf7900df1d960098177e186f0c15b6a7544491b539";
    mmr.append(node7.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        7,
        "leaves_count  should be 7"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        11,
        "elements_count  should be 11"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x763a6f33c8cf7b1411cf23910ddba74841dc4b52c73ecfb57ddc40160c78fc6"
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let hash = hasher
        .hash(vec![
            hasher
                .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                .unwrap(),
            hasher
                .hash(vec![node3.to_string(), node4.to_string()])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(
        peaks,
        vec![
            hash,
            hasher
                .hash(vec![node5.to_string(), node6.to_string()])
                .unwrap(),
            node7.to_string()
        ]
    );

    // block 9734444
    let node8 = "0x2f185aa16419cad043ddb0b75a7ba0c4233d51b7fee31f1ad6680f5c2b53677";
    mmr.append(node8.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        8,
        "leaves_count  should be 8"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        15,
        "elements_count  should be 15"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x7abaf3802dee5c46f80d30101a3882645070d0968758b2a9b7a3bc5e1a059fa"
    );
    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let hash = hasher
        .hash(vec![
            hasher
                .hash(vec![
                    hasher
                        .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                        .unwrap(),
                    hasher
                        .hash(vec![node3.to_string(), node4.to_string()])
                        .unwrap(),
                ])
                .unwrap(),
            hasher
                .hash(vec![
                    hasher
                        .hash(vec![node5.to_string(), node6.to_string()])
                        .unwrap(),
                    hasher
                        .hash(vec![node7.to_string(), node8.to_string()])
                        .unwrap(),
                ])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(peaks, vec![hash]);

    // block 9734445
    let node9 = "0x3ff20a1d65c24d07ebedb2de39c0a27e67808b49d1544e8ef972da1d24da302";
    mmr.append(node9.to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        9,
        "leaves_count  should be 9"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        16,
        "elements_count  should be 16"
    );

    let peaks = mmr
        .get_peaks(PeaksOptions {
            elements_count: None,
            formatting_opts: None,
        })
        .await
        .unwrap();
    let hash = &hasher
        .hash(vec![
            hasher
                .hash(vec![
                    hasher
                        .hash(vec![hasher.get_genesis().unwrap(), node2.to_string()])
                        .unwrap(),
                    hasher
                        .hash(vec![node3.to_string(), node4.to_string()])
                        .unwrap(),
                ])
                .unwrap(),
            hasher
                .hash(vec![
                    hasher
                        .hash(vec![node5.to_string(), node6.to_string()])
                        .unwrap(),
                    hasher
                        .hash(vec![node7.to_string(), node8.to_string()])
                        .unwrap(),
                ])
                .unwrap(),
        ])
        .unwrap();
    assert_eq!(peaks, vec![hash.to_string(), node9.to_string()]);
    assert_eq!(
        hasher
            .hash(vec![
                "16".to_string(),
                hasher
                    .hash(vec![hash.to_string(), node9.to_string()])
                    .unwrap()
            ])
            .unwrap(),
        "0x27f8b7a2ed6d1290833c6fa587d564a8810ee1925b1b2cdfde8da1cefdee57b"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    assert_eq!(elements_count, 16);
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    assert_eq!(
        bag,
        hasher
            .hash(vec![hash.to_string(), node9.to_string()])
            .unwrap()
    );
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x27f8b7a2ed6d1290833c6fa587d564a8810ee1925b1b2cdfde8da1cefdee57b"
    );

    // block 9734446
    mmr.append("0x437048beb7e0b3f95fb670e34ac4bd2f32acf6a8ad3eb5fc08682f285ad805b".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        10,
        "leaves_count  should be 10"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        18,
        "elements_count  should be 18"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        root,
        "0x2c02006787d05a482e0a19771a82c353d65a8eff7e69e1be9ae2219d0400951"
    );

    // block 9734447
    mmr.append("0x3cd2cd10c8fedcccab3691f9852b25936ef838e0c826e39ecba3354f23664cd".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        mmr.leaves_count.get().await.unwrap(),
        11,
        "leaves_count  should be 11"
    );
    assert_eq!(
        mmr.elements_count.get().await.unwrap(),
        19,
        "elements_count  should be 19"
    );
    let elements_count = mmr.elements_count.get().await.unwrap();
    let bag = mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, elements_count)
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0x06bdd6350f4f5600876f13fb1ee9be09565e37f4ab97971268bc0eb2df5ed6b9
    assert_eq!(
        root,
        "0x2ca29d4ac90ce8715232f2af120c77a4d647771d76e0720afc1fd330aa64577"
    );
}
