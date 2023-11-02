use std::vec;

use mmr::{
    core::CoreMMR,
    hash::{stark_pedersen::StarkPedersenHasher, stark_poseidon::StarkPoseidonHasher, IHasher},
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

    let append_result1 = mmr.append("1".to_string()).unwrap();

    // assert_eq!(
    //     append_result1,
    //     AppendResult {
    //         element_index: 1,
    //         leaves_count: 1,
    //         elements_count: 1,
    //         root_hash: "0x3cc2480c0b3ab9bf7749d5f767210d20d27f9c898b089d5143c4949b9b40e88"
    //             .to_string(),
    //     }
    // );

    // assert_eq!(
    //     hasher.clone().hash(vec!["1".to_string()]).unwrap(),
    //     "0x3cc2480c0b3ab9bf7749d5f767210d20d27f9c898b089d5143c4949b9b40e88"
    // );

    // assert_eq!(
    //     mmr.bag_the_peaks(None).unwrap(),
    //     "0x3cc2480c0b3ab9bf7749d5f767210d20d27f9c898b089d5143c4949b9b40e88"
    // );

    mmr.append("2".to_string());

    // assert_eq!(
    //     mmr.bag_the_peaks(None).unwrap(),
    //     "0x5ae70d29d08bfdfb53473ca943d16566a0a3bdaa249a88983402cc2653dad6c"
    // );

    mmr.append("4".to_string());
    // assert_eq!(
    //     mmr.bag_the_peaks(None).unwrap(),
    //     "0x3eb9080d3f8d76df91832f69b6d28c656de9d809eeb2173f0eefd64324453d6"
    // );
    mmr.append("5".to_string());
    // assert_eq!(
    //     mmr.bag_the_peaks(None).unwrap(),
    //     "0x1e9475eec2ef9bb365e7e132b658e32fa0d7261652d0819194202aa25334895"
    // );
    mmr.append("8".to_string());
    // assert_eq!(
    //     mmr.bag_the_peaks(None).unwrap(),
    //     "0x23a7bfa3e618bdadb56a1a29b468caaf53b533bddb7217329533fab648c2678"
    // );

    let peaks = mmr.bag_the_peaks(None).unwrap();
    // assert_eq!(
    //     peaks,
    //     "1096725095163354219926720901079039062801431726264604829411571423717521670390"
    // );

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

    assert_eq!(
        proof5,
        Proof {
            element_index: 5,
            element_hash: "0x2367a3a530bece934bc90c95820d6757e492a135ba3708021b9672b4e068004"
                .to_string(),
            siblings_hashes: vec![
                "0x1e356bc787ac099b765784e95dc8b3ef3c79de820efc4ca6dd5a3fd581d4c8f".to_string(),
                "0x380afcc28e5a9c5a0e446c4b21f5b67d65a06e683773764cab6d0d5ef79034a".to_string()
            ],
            peaks_hashes: vec![
                "0x3e4f949d5da2a812f6cad2dac70fdbe996d0c2d44836606ff50943fb859ee93".to_string(),
                "0x4760ab91edf8458183ebda97c5b3a93978f7c145fd28e6d4f1ad9aaae4441f".to_string()
            ],
            elements_count: 8
        }
    )
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

// #[test]
// fn test_genesis() {
//     let hasher = StarkPedersenHasher::new();
//     let store = SQLiteStore::new(":memory:").unwrap();
//     let _ = store.init();
//     let mmr = CoreMMR::create_with_genesis(store, hasher.clone(), None).unwrap();
//     println!("geensis hash from hasher: {}", hasher.get_genesis());
//     assert_eq!(
//         mmr.root_hash.get(None).unwrap_or_default(),
//         hasher.hash(vec!["1".to_string(), hasher.get_genesis()])
//     );
// }

// it("should generate mmr with genesis for keccak hasher", async () => {
//     const hasher = new KeccakHasher();
//     const mmr = await CoreMMR.createWithGenesis(new MemoryStore(), hasher);
//     expect(await mmr.rootHash.get()).toEqual(hasher.hash(["1", hasher.getGenesis()]));
//   });
// import CoreMMR, { DraftMMR } from "../src";
// import { StarkPedersenHasher } from "@accumulators/hashers";
// import MemoryStore from "@accumulators/memory";

// const store = new MemoryStore();
// const storeDraft = new MemoryStore();
// const hasher = new StarkPedersenHasher();

// describe("precomputation", () => {
//   let mmr: CoreMMR;
//   const rootAt6Leaves = "0x03203d652ecaf8ad941cbbccddcc0ce904d81e2c37e6dcff4377cf988dac493c";

//   beforeEach(async () => {
//     mmr = new CoreMMR(store, hasher);
//     await mmr.append("1");
//     await mmr.append("2");
//     await mmr.append("3");
//   });

//   it("should compute parent tree", async () => {
//     await mmr.append("4");
//     const { elementIndex } = await mmr.append("5");
//     await mmr.append("6");

//     await expect(mmr.bagThePeaks()).resolves.toEqual(rootAt6Leaves);
//     const proof = await mmr.getProof(elementIndex);
//     await expect(mmr.verifyProof(proof, "5")).resolves.toEqual(true);
//   });

//   it("should precompute from parent tree", async () => {
//     const precomputationMmr = await DraftMMR.initialize(storeDraft, hasher, mmr, "precomputed");

//     await precomputationMmr.append("4");
//     const { elementIndex } = await precomputationMmr.append("5");
//     await precomputationMmr.append("6");

//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual(rootAt6Leaves);
//     const proof = await precomputationMmr.getProof(elementIndex);
//     await expect(precomputationMmr.verifyProof(proof, "5")).resolves.toEqual(true);

//     await precomputationMmr.discard();
//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual("0x0");

//     //? After closing the precomputation, the parent MMR should still work
//     await mmr.append("4");
//     const { elementIndex: parentLeafElementIndex } = await mmr.append("5");
//     await mmr.append("6");
//     await expect(mmr.bagThePeaks()).resolves.toEqual(rootAt6Leaves);
//     const parentProof = await mmr.getProof(parentLeafElementIndex);
//     await expect(mmr.verifyProof(parentProof, "5")).resolves.toEqual(true);
//   });

//   it("should apply Draft mmr", async () => {
//     const precomputationMmr = await DraftMMR.initialize(storeDraft, hasher, mmr, "precomputed");

//     await precomputationMmr.append("4");
//     const { elementIndex } = await precomputationMmr.append("5");
//     await precomputationMmr.append("6");

//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual(rootAt6Leaves);
//     const proof = await precomputationMmr.getProof(elementIndex);
//     await expect(precomputationMmr.verifyProof(proof, "5")).resolves.toEqual(true);

//     await precomputationMmr.apply();
//     //? After applying the precomputation, the parent MMR should work
//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual("0x0");
//     await expect(mmr.bagThePeaks()).resolves.toEqual(rootAt6Leaves);
//     const parentProof = await mmr.getProof(elementIndex);
//     await expect(mmr.verifyProof(parentProof, "5")).resolves.toEqual(true);
//   });
// });

// describe("empty mmr", () => {
//   let mmr: CoreMMR;

//   beforeEach(async () => {
//     mmr = new CoreMMR(store, hasher);
//   });

//   it("should precompute from empty mmr", async () => {
//     const precomputationMmr = await DraftMMR.initialize(storeDraft, hasher, mmr, "precomputed");

//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual("0x0");

//     await precomputationMmr.append("1");
//     await precomputationMmr.append("2");

//     await expect(precomputationMmr.bagThePeaks()).resolves.toEqual(
//       "0x05bb9440e27889a364bcb678b1f679ecd1347acdedcbf36e83494f857cc58026"
//     );

//     await precomputationMmr.discard();
//   });
// });

// afterAll(async () => {
//   await expect(storeDraft.store.size).toBe(0);
// });
