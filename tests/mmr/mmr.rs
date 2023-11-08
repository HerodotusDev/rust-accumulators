use std::rc::Rc;

use accumulators::{
    hasher::{stark_poseidon::StarkPoseidonHasher, Hasher},
    mmr::{
        helpers::{AppendResult, Proof, ProofOptions},
        CoreMMR, MMR,
    },
    store::{sqlite::SQLiteStore, table::SubKey},
};

#[test]
fn should_append_to_mmr() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let store = Rc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    // Act
    // let mut mmr = CoreMMR::create_with_genesis(store, hasher.clone(), None).unwrap();
    let append_result1 = mmr.append("1".to_string()).unwrap();

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

    assert_eq!(mmr.bag_the_peaks(None).unwrap(), "1");

    let append_result2 = mmr.append("2".to_string()).unwrap();

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
        mmr.bag_the_peaks(None).unwrap(),
        "0x5d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a"
    );

    let append_result4 = mmr.append("4".to_string()).unwrap();
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
        mmr.bag_the_peaks(None).unwrap(),
        "0x6f31a64a67c46b553960ae6b72bcf9fa3ccc6a4d6344e3799412e2c73a059b2"
    );
    let append_result5 = mmr.append("5".to_string()).unwrap();
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
        mmr.bag_the_peaks(None).unwrap(),
        "0x43c59debacab61e73dec9edd73da27738a8be14c1e123bb38f9634220323c4f"
    );
    let append_result8 = mmr.append("8".to_string()).unwrap();
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
        mmr.bag_the_peaks(None).unwrap(),
        "0x49da356656c3153d59f9be39143daebfc12e05b6a93ab4ccfa866a890ad78f"
    );

    let proof1 = mmr
        .get_proof(
            1,
            ProofOptions {
                elements_count: None,
                formatting_opts: None,
            },
        )
        .unwrap();

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

    mmr.verify_proof(
        proof1,
        "1".to_string(),
        ProofOptions {
            elements_count: None,
            formatting_opts: None,
        },
    )
    .unwrap();

    let proof2 = mmr
        .get_proof(
            2,
            ProofOptions {
                elements_count: None,
                formatting_opts: None,
            },
        )
        .unwrap();

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

    mmr.verify_proof(
        proof2,
        "2".to_string(),
        ProofOptions {
            elements_count: None,
            formatting_opts: None,
        },
    )
    .unwrap();

    let proof4 = mmr
        .get_proof(
            4,
            ProofOptions {
                elements_count: None,
                formatting_opts: None,
            },
        )
        .unwrap();

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

    mmr.verify_proof(
        proof4,
        "4".to_string(),
        ProofOptions {
            elements_count: None,
            formatting_opts: None,
        },
    )
    .unwrap();

    let proof5 = mmr
        .get_proof(
            5,
            ProofOptions {
                elements_count: None,
                formatting_opts: None,
            },
        )
        .unwrap();

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

    mmr.verify_proof(
        proof5,
        "5".to_string(),
        ProofOptions {
            elements_count: None,
            formatting_opts: None,
        },
    )
    .unwrap();
}

#[test]
fn should_append_duplicate_to_mmr() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let _ = store.init();
    let store = Rc::new(store);

    let mut mmr = MMR::new(store, hasher, None);
    let _ = mmr.append("4".to_string());
    let _ = mmr.append("4".to_string());

    let _root = mmr.bag_the_peaks(None).unwrap();
}

#[test]
fn test_new() {
    // Arrange
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let _ = store.init();
    let store = Rc::new(store);

    // Act
    let core_mmr = MMR::create_with_genesis(store, hasher.clone(), None).unwrap();

    assert_eq!(
        core_mmr.root_hash.get(SubKey::None).unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis()])
            .unwrap()
    );
}
