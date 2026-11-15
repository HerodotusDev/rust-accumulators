//! Serde implementations: hashes and ids as `"0x"`-prefixed lowercase hex,
//! indexes and sizes as plain numbers.
//!
//! Enabled by the `serde` feature. Crate-owned types get direct impls;
//! foreign [`HashValue`](crate::primitives::HashValue) outputs — e.g.
//! `starknet_crypto::Felt`, which the orphan rule forbids implementing serde
//! for here — go through the
//! [`HexHash`](crate::serde_impls::HexHash) adapter. Its deserialization is
//! the output type's own checked
//! [`HashValue::from_bytes`](crate::primitives::HashValue::from_bytes), so a
//! felt at or above the field modulus is a serde error: never a panic, never
//! a wrapped value.
//!
//! Deserialization validates the *encoding* — hex well-formedness, lengths,
//! index ranges — and nothing more. A deserialized proof is not verified:
//! crypto validation is `verify`'s job, by design.
//!
//! ```
//! use accumulators::hashers::{Hasher, KeccakSolHasher};
//! use accumulators::ids::AccumulatorId;
//! use accumulators::mmr::Mmr;
//! use accumulators::primitives::{Hash, LeafIndex};
//! use accumulators::store::memory::InMemoryStore;
//!
//! let mut mmr: Mmr<KeccakSolHasher, _> =
//!     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO).unwrap();
//! mmr.append(b"element").unwrap();
//! let proof = mmr.proof(LeafIndex::FIRST).unwrap();
//!
//! let json = serde_json::to_string(&proof).unwrap();
//! let round_tripped: accumulators::mmr::Proof<Hash> = serde_json::from_str(&json).unwrap();
//! assert_eq!(round_tripped, proof);
//! assert!(mmr.verify(&round_tripped, b"element").unwrap());
//!
//! let hash_json = serde_json::to_string(&Hash::from_u64(1)).unwrap();
//! assert_eq!(hash_json, format!("\"0x{}\"", Hash::from_u64(1)));
//! ```

use core::fmt;
use core::marker::PhantomData;

use serde::de::{self, DeserializeSeed, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "mmr")]
use serde::de::{EnumAccess, IgnoredAny, MapAccess, SeqAccess, VariantAccess};
#[cfg(feature = "mmr")]
use serde::ser::{SerializeStruct, SerializeStructVariant};

use crate::ids::AccumulatorId;
use crate::primitives::{Hash, HashValue};

#[cfg(feature = "mmr")]
use crate::mmr::layout::MmrSize;
#[cfg(feature = "mmr")]
use crate::mmr::nullifiers::NullifierRecord;
#[cfg(feature = "mmr")]
use crate::mmr::{ConsistencyProof, MultiProof, Proof};
#[cfg(feature = "mmr")]
use crate::primitives::LeafIndex;

/// `"0x"` + lowercase canonical hex of a hash value.
fn hash_to_hex<O: HashValue>(value: &O) -> alloc::string::String {
    alloc::format!("0x{}", crate::primitives::hex::encode(&value.to_vec()))
}

/// Hex strings for a list of hash values.
#[cfg(feature = "mmr")]
fn hashes_to_hex<'a, O: HashValue + 'a>(
    values: impl IntoIterator<Item = &'a O>,
) -> alloc::vec::Vec<alloc::string::String> {
    values.into_iter().map(hash_to_hex).collect()
}

/// Parses a hex string into a hash value: length- and hex-checked, then
/// rebuilt through the type's checked [`HashValue::from_bytes`] (which
/// rejects out-of-range values such as a felt ≥ the field modulus).
fn hash_from_hex<O: HashValue, E: de::Error>(s: &str) -> Result<O, E> {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    if hex.len() != O::LEN * 2 {
        return Err(E::custom(format_args!(
            "expected {} hex characters for the hash, found {}",
            O::LEN * 2,
            hex.len()
        )));
    }
    let mut bytes = alloc::vec![0_u8; O::LEN];
    crate::primitives::hex::decode_into(hex, &mut bytes).map_err(|_| E::custom("invalid hex"))?;
    O::from_bytes(&bytes).ok_or_else(|| E::custom("value out of range for the hash type"))
}

/// Deserializing seed for one hex-encoded hash value.
struct HashSeed<O: HashValue>(PhantomData<fn() -> O>);

impl<'de, O: HashValue> de::DeserializeSeed<'de> for HashSeed<O> {
    type Value = O;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct HexVisitor<O: HashValue>(PhantomData<fn() -> O>);

        impl<O: HashValue> Visitor<'_> for HexVisitor<O> {
            type Value = O;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a hex-encoded hash value of {} bytes", O::LEN)
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                hash_from_hex(s)
            }
        }

        deserializer.deserialize_str(HexVisitor(PhantomData))
    }
}

/// Deserializing seed for a list of hex-encoded hash values.
#[cfg(feature = "mmr")]
struct HashListSeed<O: HashValue>(PhantomData<fn() -> O>);

#[cfg(feature = "mmr")]
impl<O: HashValue> Default for HashListSeed<O> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> de::DeserializeSeed<'de> for HashListSeed<O> {
    type Value = alloc::vec::Vec<O>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct ListVisitor<O: HashValue>(PhantomData<fn() -> O>);

        impl<'de, O: HashValue> Visitor<'de> for ListVisitor<O> {
            type Value = alloc::vec::Vec<O>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a list of hex-encoded hash values")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = alloc::vec::Vec::new();
                while let Some(value) = seq.next_element_seed(HashSeed(PhantomData))? {
                    out.push(value);
                }
                Ok(out)
            }
        }

        deserializer.deserialize_seq(ListVisitor(PhantomData))
    }
}

/// Deserializes a `u64` into an [`MmrSize`] that is a well-formed MMR size.
#[cfg(feature = "mmr")]
fn size_from_u64<E: de::Error>(raw: u64) -> Result<MmrSize, E> {
    MmrSize::try_new(raw)
        .ok_or_else(|| E::custom(format_args!("{raw} is not a well-formed MMR size")))
}

/// Deserializes a `u64` into an in-range [`LeafIndex`].
#[cfg(feature = "mmr")]
fn leaf_from_u64<E: de::Error>(raw: u64) -> Result<LeafIndex, E> {
    LeafIndex::try_new(raw).ok_or_else(|| E::custom(format_args!("{raw} is out of the leaf range")))
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&alloc::format!("0x{self}"))
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HashVisitor;

        impl Visitor<'_> for HashVisitor {
            type Value = Hash;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 64-character hex hash (leading `0x` tolerated)")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                s.parse().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(HashVisitor)
    }
}

impl Serialize for AccumulatorId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&alloc::format!("0x{self}"))
    }
}

impl<'de> Deserialize<'de> for AccumulatorId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor;

        impl Visitor<'_> for IdVisitor {
            type Value = AccumulatorId;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 32-character hex accumulator id")
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                let hex = s.strip_prefix("0x").unwrap_or(s);
                hex.parse().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(IdVisitor)
    }
}

/// Serde adapter for foreign [`HashValue`] types: `"0x"`-prefixed lowercase
/// hex, deserialized through the output type's own checked
/// [`HashValue::from_bytes`].
///
/// Crate-owned hash outputs ([`struct@Hash`]) have direct impls; this wrapper is
/// for types the crate cannot implement serde for — `starknet_crypto::Felt`
/// and any user-defined foreign output. A value that fails the checked
/// conversion (a felt ≥ the field modulus) is a serde error, never a panic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexHash<O: HashValue>(pub O);

impl<O: HashValue> From<O> for HexHash<O> {
    fn from(value: O) -> Self {
        Self(value)
    }
}

impl<O: HashValue> Serialize for HexHash<O> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hash_to_hex(&self.0))
    }
}

impl<'de, O: HashValue> Deserialize<'de> for HexHash<O> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        HashSeed(PhantomData).deserialize(deserializer).map(Self)
    }
}

/// Serializes a [`NullifierRecord`] as its externally tagged enum:
/// `{"Shallow": {"at": <size>}}` / `"Deep"`.
#[cfg(feature = "mmr")]
impl Serialize for NullifierRecord {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Shallow { at } => {
                let mut state =
                    serializer.serialize_struct_variant("NullifierRecord", 0, "Shallow", 1)?;
                state.serialize_field("at", &at.get())?;
                state.end()
            }
            Self::Deep => serializer.serialize_unit_variant("NullifierRecord", 1, "Deep"),
        }
    }
}

#[cfg(feature = "mmr")]
impl<'de> Deserialize<'de> for NullifierRecord {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const VARIANTS: &[&str] = &["Shallow", "Deep"];

        struct RecordVisitor;

        impl<'de> Visitor<'de> for RecordVisitor {
            type Value = NullifierRecord;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a nullifier record (Shallow { at } or Deep)")
            }

            fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<Self::Value, A::Error> {
                match data.variant::<&str>()? {
                    ("Shallow", variant) => variant.struct_variant(&["at"], AtVisitor),
                    ("Deep", variant) => variant.unit_variant().map(|()| Self::Value::Deep),
                    (tag, _) => Err(de::Error::unknown_variant(tag, VARIANTS)),
                }
            }
        }

        struct AtVisitor;

        impl<'de> Visitor<'de> for AtVisitor {
            type Value = NullifierRecord;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Shallow nullifier record with an `at` MMR size")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let at = seq
                    .next_element::<u64>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &"NullifierRecord::Shallow"))?;
                shallow_from_u64(at)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut at: Option<u64> = None;
                while let Some(key) = map.next_key::<&str>()? {
                    match key {
                        "at" => {
                            if at.is_some() {
                                return Err(de::Error::duplicate_field("at"));
                            }
                            at = Some(map.next_value()?);
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                let at = at.ok_or_else(|| de::Error::missing_field("at"))?;
                shallow_from_u64(at)
            }
        }

        deserializer.deserialize_enum("NullifierRecord", VARIANTS, RecordVisitor)
    }
}

/// Rebuilds a shallow record from its raw size, rejecting the wire's deep
/// marker (`0`) and non-well-formed sizes.
#[cfg(feature = "mmr")]
fn shallow_from_u64<E: de::Error>(raw: u64) -> Result<NullifierRecord, E> {
    if raw == 0 {
        return Err(E::custom(
            "shallow nullifier size 0 is the deep marker (serialize Deep instead)",
        ));
    }
    MmrSize::try_new(raw)
        .map(|at| NullifierRecord::Shallow { at })
        .ok_or_else(|| E::custom(format_args!("{raw} is not a well-formed MMR size")))
}

#[cfg(feature = "mmr")]
impl<O: HashValue> Serialize for Proof<O> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("Proof", 6)?;
        state.serialize_field("leaf", &self.leaf.get())?;
        state.serialize_field("element_hash", &hash_to_hex(&self.element_hash))?;
        state.serialize_field("siblings", &hashes_to_hex(&self.siblings))?;
        state.serialize_field("peaks", &hashes_to_hex(&self.peaks))?;
        state.serialize_field("root", &hash_to_hex(&self.root))?;
        state.serialize_field("size", &self.size.get())?;
        state.end()
    }
}

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Deserialize<'de> for Proof<O> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &["leaf", "element_hash", "siblings", "peaks", "root", "size"];
        deserializer.deserialize_struct("Proof", FIELDS, ProofVisitor(PhantomData))
    }
}

#[cfg(feature = "mmr")]
struct ProofVisitor<O: HashValue>(PhantomData<fn() -> O>);

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Visitor<'de> for ProofVisitor<O> {
    type Value = Proof<O>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a self-contained MMR proof")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        const EXPECTING: &str = "Proof with 6 fields";
        let leaf = leaf_from_u64(
            seq.next_element::<u64>()?
                .ok_or_else(|| de::Error::invalid_length(0, &EXPECTING))?,
        )?;
        let element_hash = seq
            .next_element_seed(HashSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(1, &EXPECTING))?;
        let siblings = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(2, &EXPECTING))?;
        let peaks = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(3, &EXPECTING))?;
        let root = seq
            .next_element_seed(HashSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(4, &EXPECTING))?;
        let size = size_from_u64(
            seq.next_element::<u64>()?
                .ok_or_else(|| de::Error::invalid_length(5, &EXPECTING))?,
        )?;
        Ok(Self::Value {
            leaf,
            element_hash,
            siblings,
            peaks,
            root,
            size,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut leaf: Option<u64> = None;
        let mut element_hash: Option<O> = None;
        let mut siblings: Option<alloc::vec::Vec<O>> = None;
        let mut peaks: Option<alloc::vec::Vec<O>> = None;
        let mut root: Option<O> = None;
        let mut size: Option<u64> = None;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "leaf" => {
                    if leaf.is_some() {
                        return Err(de::Error::duplicate_field("leaf"));
                    }
                    leaf = Some(map.next_value()?);
                }
                "element_hash" => {
                    if element_hash.is_some() {
                        return Err(de::Error::duplicate_field("element_hash"));
                    }
                    element_hash = Some(map.next_value_seed(HashSeed(PhantomData))?);
                }
                "siblings" => {
                    if siblings.is_some() {
                        return Err(de::Error::duplicate_field("siblings"));
                    }
                    siblings = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "peaks" => {
                    if peaks.is_some() {
                        return Err(de::Error::duplicate_field("peaks"));
                    }
                    peaks = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "root" => {
                    if root.is_some() {
                        return Err(de::Error::duplicate_field("root"));
                    }
                    root = Some(map.next_value_seed(HashSeed(PhantomData))?);
                }
                "size" => {
                    if size.is_some() {
                        return Err(de::Error::duplicate_field("size"));
                    }
                    size = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Self::Value {
            leaf: leaf_from_u64(leaf.ok_or_else(|| de::Error::missing_field("leaf"))?)?,
            element_hash: element_hash.ok_or_else(|| de::Error::missing_field("element_hash"))?,
            siblings: siblings.ok_or_else(|| de::Error::missing_field("siblings"))?,
            peaks: peaks.ok_or_else(|| de::Error::missing_field("peaks"))?,
            root: root.ok_or_else(|| de::Error::missing_field("root"))?,
            size: size_from_u64(size.ok_or_else(|| de::Error::missing_field("size"))?)?,
        })
    }
}

#[cfg(feature = "mmr")]
impl<O: HashValue> Serialize for MultiProof<O> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("MultiProof", 7)?;
        state.serialize_field(
            "leaves",
            &self
                .leaves
                .iter()
                .map(|leaf| leaf.get())
                .collect::<alloc::vec::Vec<_>>(),
        )?;
        state.serialize_field("element_hashes", &hashes_to_hex(&self.element_hashes))?;
        state.serialize_field("sibling_pool", &hashes_to_hex(&self.sibling_pool))?;
        state.serialize_field("sibling_refs", &self.sibling_refs)?;
        state.serialize_field("peaks", &hashes_to_hex(&self.peaks))?;
        state.serialize_field("root", &hash_to_hex(&self.root))?;
        state.serialize_field("size", &self.size.get())?;
        state.end()
    }
}

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Deserialize<'de> for MultiProof<O> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &[
            "leaves",
            "element_hashes",
            "sibling_pool",
            "sibling_refs",
            "peaks",
            "root",
            "size",
        ];
        deserializer.deserialize_struct("MultiProof", FIELDS, MultiProofVisitor(PhantomData))
    }
}

#[cfg(feature = "mmr")]
struct MultiProofVisitor<O: HashValue>(PhantomData<fn() -> O>);

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Visitor<'de> for MultiProofVisitor<O> {
    type Value = MultiProof<O>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a deduplicated MMR multiproof")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        const EXPECTING: &str = "MultiProof with 7 fields";
        let leaves = leaves_from_u64(
            seq.next_element::<alloc::vec::Vec<u64>>()?
                .ok_or_else(|| de::Error::invalid_length(0, &EXPECTING))?,
        )?;
        let element_hashes = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(1, &EXPECTING))?;
        let sibling_pool = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(2, &EXPECTING))?;
        let sibling_refs = seq
            .next_element::<alloc::vec::Vec<u32>>()?
            .ok_or_else(|| de::Error::invalid_length(3, &EXPECTING))?;
        let peaks = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(4, &EXPECTING))?;
        let root = seq
            .next_element_seed(HashSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(5, &EXPECTING))?;
        let size = size_from_u64(
            seq.next_element::<u64>()?
                .ok_or_else(|| de::Error::invalid_length(6, &EXPECTING))?,
        )?;
        Ok(Self::Value {
            leaves,
            element_hashes,
            sibling_pool,
            sibling_refs,
            peaks,
            root,
            size,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut leaves: Option<alloc::vec::Vec<u64>> = None;
        let mut element_hashes: Option<alloc::vec::Vec<O>> = None;
        let mut sibling_pool: Option<alloc::vec::Vec<O>> = None;
        let mut sibling_refs: Option<alloc::vec::Vec<u32>> = None;
        let mut peaks: Option<alloc::vec::Vec<O>> = None;
        let mut root: Option<O> = None;
        let mut size: Option<u64> = None;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "leaves" => {
                    if leaves.is_some() {
                        return Err(de::Error::duplicate_field("leaves"));
                    }
                    leaves = Some(map.next_value()?);
                }
                "element_hashes" => {
                    if element_hashes.is_some() {
                        return Err(de::Error::duplicate_field("element_hashes"));
                    }
                    element_hashes = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "sibling_pool" => {
                    if sibling_pool.is_some() {
                        return Err(de::Error::duplicate_field("sibling_pool"));
                    }
                    sibling_pool = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "sibling_refs" => {
                    if sibling_refs.is_some() {
                        return Err(de::Error::duplicate_field("sibling_refs"));
                    }
                    sibling_refs = Some(map.next_value()?);
                }
                "peaks" => {
                    if peaks.is_some() {
                        return Err(de::Error::duplicate_field("peaks"));
                    }
                    peaks = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "root" => {
                    if root.is_some() {
                        return Err(de::Error::duplicate_field("root"));
                    }
                    root = Some(map.next_value_seed(HashSeed(PhantomData))?);
                }
                "size" => {
                    if size.is_some() {
                        return Err(de::Error::duplicate_field("size"));
                    }
                    size = Some(map.next_value()?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Self::Value {
            leaves: leaves_from_u64(leaves.ok_or_else(|| de::Error::missing_field("leaves"))?)?,
            element_hashes: element_hashes
                .ok_or_else(|| de::Error::missing_field("element_hashes"))?,
            sibling_pool: sibling_pool.ok_or_else(|| de::Error::missing_field("sibling_pool"))?,
            sibling_refs: sibling_refs.ok_or_else(|| de::Error::missing_field("sibling_refs"))?,
            peaks: peaks.ok_or_else(|| de::Error::missing_field("peaks"))?,
            root: root.ok_or_else(|| de::Error::missing_field("root"))?,
            size: size_from_u64(size.ok_or_else(|| de::Error::missing_field("size"))?)?,
        })
    }
}

/// Rebuilds leaf indexes from raw values, rejecting out-of-range entries.
#[cfg(feature = "mmr")]
fn leaves_from_u64<E: de::Error>(
    raw: alloc::vec::Vec<u64>,
) -> Result<alloc::vec::Vec<LeafIndex>, E> {
    raw.into_iter().map(leaf_from_u64).collect()
}

#[cfg(feature = "mmr")]
impl<O: HashValue> Serialize for ConsistencyProof<O> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ConsistencyProof", 4)?;
        state.serialize_field("prev_size", &self.prev_size.get())?;
        state.serialize_field("size", &self.size.get())?;
        state.serialize_field("prev_peaks", &hashes_to_hex(&self.prev_peaks))?;
        state.serialize_field("path", &hashes_to_hex(&self.path))?;
        state.end()
    }
}

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Deserialize<'de> for ConsistencyProof<O> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const FIELDS: &[&str] = &["prev_size", "size", "prev_peaks", "path"];
        deserializer.deserialize_struct(
            "ConsistencyProof",
            FIELDS,
            ConsistencyProofVisitor(PhantomData),
        )
    }
}

#[cfg(feature = "mmr")]
struct ConsistencyProofVisitor<O: HashValue>(PhantomData<fn() -> O>);

#[cfg(feature = "mmr")]
impl<'de, O: HashValue> Visitor<'de> for ConsistencyProofVisitor<O> {
    type Value = ConsistencyProof<O>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a self-contained MMR consistency proof")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        const EXPECTING: &str = "ConsistencyProof with 4 fields";
        let prev_size = size_from_u64(
            seq.next_element::<u64>()?
                .ok_or_else(|| de::Error::invalid_length(0, &EXPECTING))?,
        )?;
        let size = size_from_u64(
            seq.next_element::<u64>()?
                .ok_or_else(|| de::Error::invalid_length(1, &EXPECTING))?,
        )?;
        let prev_peaks = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(2, &EXPECTING))?;
        let path = seq
            .next_element_seed(HashListSeed(PhantomData))?
            .ok_or_else(|| de::Error::invalid_length(3, &EXPECTING))?;
        Ok(Self::Value {
            prev_size,
            size,
            prev_peaks,
            path,
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut prev_size: Option<u64> = None;
        let mut size: Option<u64> = None;
        let mut prev_peaks: Option<alloc::vec::Vec<O>> = None;
        let mut path: Option<alloc::vec::Vec<O>> = None;
        while let Some(key) = map.next_key::<&str>()? {
            match key {
                "prev_size" => {
                    if prev_size.is_some() {
                        return Err(de::Error::duplicate_field("prev_size"));
                    }
                    prev_size = Some(map.next_value()?);
                }
                "size" => {
                    if size.is_some() {
                        return Err(de::Error::duplicate_field("size"));
                    }
                    size = Some(map.next_value()?);
                }
                "prev_peaks" => {
                    if prev_peaks.is_some() {
                        return Err(de::Error::duplicate_field("prev_peaks"));
                    }
                    prev_peaks = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                "path" => {
                    if path.is_some() {
                        return Err(de::Error::duplicate_field("path"));
                    }
                    path = Some(map.next_value_seed(HashListSeed(PhantomData))?);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Self::Value {
            prev_size: size_from_u64(
                prev_size.ok_or_else(|| de::Error::missing_field("prev_size"))?,
            )?,
            size: size_from_u64(size.ok_or_else(|| de::Error::missing_field("size"))?)?,
            prev_peaks: prev_peaks.ok_or_else(|| de::Error::missing_field("prev_peaks"))?,
            path: path.ok_or_else(|| de::Error::missing_field("path"))?,
        })
    }
}
