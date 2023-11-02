use std::vec;

use mmr::{
    core::CoreMMR,
    hash::{stark_poseidon::StarkPoseidonHasher, IHasher},
    helpers::AppendResult,
    proof::{Proof, ProofOptions},
    store::sqlite::SQLiteStore,
};

#[test]
fn should_append_to_mmr() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let _ = store.init();

    let mut mmr = CoreMMR::new(store, hasher.clone(), None);

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
        "0x2241b3b7f1c4b9cf63e670785891de91f7237b1388f6635c1898ae397ad32dd"
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

    // assert_eq!(
    //     proof5,
    //     Proof {
    //         element_index: 5,
    //         element_hash: "0x2367a3a530bece934bc90c95820d6757e492a135ba3708021b9672b4e068004"
    //             .to_string(),
    //         siblings_hashes: vec![
    //             "0x1e356bc787ac099b765784e95dc8b3ef3c79de820efc4ca6dd5a3fd581d4c8f".to_string(),
    //             "0x380afcc28e5a9c5a0e446c4b21f5b67d65a06e683773764cab6d0d5ef79034a".to_string()
    //         ],
    //         peaks_hashes: vec![
    //             "0x3e4f949d5da2a812f6cad2dac70fdbe996d0c2d44836606ff50943fb859ee93".to_string(),
    //             "0x4760ab91edf8458183ebda97c5b3a93978f7c145fd28e6d4f1ad9aaae4441f".to_string()
    //         ],
    //         elements_count: 8
    //     }
    // )
}

#[test]
fn should_append_duplicate_to_mmr() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let _ = store.init();
    let mut mmr = CoreMMR::new(store, hasher, None);
    mmr.append("4".to_string());
    mmr.append("4".to_string());

    let root = mmr.bag_the_peaks(None).unwrap();
    println!("root:{}", root);
}

#[test]
fn test_new() {
    // Arrange
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let _ = store.init();

    // Act
    let core_mmr = CoreMMR::create_with_genesis(store, hasher.clone(), None).unwrap();

    assert_eq!(
        core_mmr.root_hash.get::<usize>(None).unwrap(),
        hasher
            .hash(vec!["1".to_string(), hasher.get_genesis()])
            .unwrap()
    );
}
