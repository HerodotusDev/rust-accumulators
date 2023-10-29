use mmr::{
    core::CoreMMR,
    hash::{stark_pedersen::StarkPedersenHasher, IHasher},
    store::sqlite::SQLiteStore,
    utils::AppendResult,
};

// #[test]
// fn test_new() {
//     let leaves = vec!["1", "2", "3"];
//     let rootAt6Leaves = "0x03203d652ecaf8ad941cbbccddcc0ce904d81e2c37e6dcff4377cf988dac493c";

//     // Arrange
//     let store = SQLiteStore::new(":memory:").unwrap();
//     let hasher = StarkPedersenHasher::new();
//     let _ = store.init();

//     // Act
//     let mut core_mmr = CoreMMR::new(store, hasher, None);
//     let mut appends_results: Vec<AppendResult> = Vec::new();
//     for leaf in leaves {
//         let result = core_mmr.append(leaf.to_string());
//         match result {
//             Ok(r) => appends_results.push(r),
//             Err(e) => panic!("Append failed: {}", e),
//         }
//     }
//     core_mmr.append("4".to_string());
//     let element_index = core_mmr.append("5".to_string()).unwrap();
//     core_mmr.append("6".to_string());

//     assert_eq!(
//         core_mmr.bag_the_peaks(None).unwrap(),
//         rootAt6Leaves.to_string()
//     );
// }

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
