use anyhow::{anyhow, bail, Result};

use indexmap::IndexMap;
use std::{collections::HashMap, sync::Arc};

use uuid::Uuid;

use crate::{
    hasher::Hasher,
    store::{InStoreTable, Store, SubKey},
};

#[derive(Debug)]
pub enum TreeMetadataKeys {
    RootHash,
}

#[derive(Debug)]
struct Node {
    hash: String,
    index: usize,
    depth: usize,
}

pub struct IncrementalMerkleTree<H> {
    pub store: Arc<dyn Store>,
    pub mmr_id: String,
    pub nodes: InStoreTable,
    pub root_hash: InStoreTable,
    pub hasher: H,
    pub size: usize,
    pub null_value: String,
}

impl<H> IncrementalMerkleTree<H>
where
    H: Hasher,
{
    fn new(
        size: usize,
        null_value: String,
        hasher: H,
        store: Arc<dyn Store>,
        mmr_id: Option<String>,
    ) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let root_hash_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::RootHash);
        let nodes_key = format!("{}:nodes:", mmr_id);

        let root_hash = InStoreTable::new(store.clone(), root_hash_key);
        let nodes = InStoreTable::new(store.clone(), nodes_key);

        Self {
            store,
            mmr_id,
            nodes,
            root_hash,
            hasher,
            size,
            null_value,
        }
    }

    pub async fn initialize(
        size: usize,
        null_value: String,
        hasher: H,
        store: Arc<dyn Store>,
        mmr_id: Option<String>,
    ) -> Self {
        let tree = IncrementalMerkleTree::new(size, null_value, hasher, store, mmr_id);
        let nodes = tree.render_empty_tree();
        let nodes_hashmap: HashMap<SubKey, String> =
            nodes
                .iter()
                .flatten()
                .fold(HashMap::new(), |mut acc, curr| {
                    let key = SubKey::String(format!("{}:{}", curr.depth, curr.index));
                    acc.insert(key, curr.hash.clone());
                    acc
                });

        tree.nodes.set_many(nodes_hashmap).await;

        tree.root_hash
            .set(&nodes[nodes.len() - 1][0].hash, SubKey::None)
            .await;
        tree
    }

    pub async fn get_root(&self) -> String {
        self.root_hash.get(SubKey::None).await.unwrap()
    }

    pub async fn get_inclusion_proof(&self, index: usize) -> Result<Vec<String>> {
        let mut required_nodes_by_height = Vec::new();
        let tree_depth = self.get_tree_depth();
        let mut current_index = index;

        for i in (1..=tree_depth).rev() {
            let is_current_index_even = current_index % 2 == 0;
            let neighbour = if is_current_index_even {
                current_index + 1
            } else {
                current_index - 1
            };
            current_index /= 2;
            required_nodes_by_height.push((i, neighbour));
        }

        let kv_entries: Vec<SubKey> = required_nodes_by_height
            .iter()
            .map(|(height, index)| SubKey::String(format!("{}:{}", height, index)))
            .collect();

        let nodes_hash_map = self.nodes.get_many(kv_entries).await;

        let mut ordered_nodes = Vec::with_capacity(required_nodes_by_height.len());
        for (height, index) in required_nodes_by_height {
            if let Some(node) = nodes_hash_map.get(&format!("{}:{}", height, index)) {
                ordered_nodes.push(node.to_string());
            }
        }
        Ok(ordered_nodes)
    }

    pub async fn verify_proof(
        &self,
        index: usize,
        value: &str,
        proof: &Vec<String>,
    ) -> Result<bool> {
        let mut current_index = index;
        let mut current_value = value.to_string();

        for p in proof {
            let is_current_index_even = current_index % 2 == 0;
            current_value = if is_current_index_even {
                self.hasher
                    .hash(vec![current_value.to_string(), p.to_string()])
                    .unwrap()
            } else {
                self.hasher
                    .hash(vec![p.to_string(), current_value.to_string()])
                    .unwrap()
            };
            current_index /= 2;
        }

        let root = self.root_hash.get(SubKey::None).await.unwrap();
        Ok(root == current_value)
    }

    pub async fn update(
        &self,
        index: usize,
        old_value: String,
        new_value: String,
        proof: Vec<String>,
    ) -> Result<String> {
        let is_proof_valid = self.verify_proof(index, &old_value, &proof).await.unwrap();
        if !is_proof_valid {
            bail!("Invalid proof");
        }

        let mut kv_updates: HashMap<SubKey, String> = HashMap::new();
        let mut current_index = index;
        let mut current_depth = self.get_tree_depth();
        let mut current_value = new_value;

        kv_updates.insert(
            SubKey::String(format!("{}:{}", current_depth, current_index)),
            current_value.clone(),
        );
        for p in proof {
            let is_current_index_even = current_index % 2 == 0;

            current_value = if is_current_index_even {
                self.hasher
                    .hash(vec![current_value.to_string(), p.to_string()])
                    .unwrap()
            } else {
                self.hasher
                    .hash(vec![p.to_string(), current_value.to_string()])
                    .unwrap()
            };

            current_depth -= 1;
            current_index /= 2;
            if current_depth == 0 {
                break;
            }
            kv_updates.insert(
                SubKey::String(format!("{}:{}", current_depth, current_index)),
                current_value.clone(),
            );
        }

        self.nodes.set_many(kv_updates).await;
        self.root_hash.set(&current_value, SubKey::None).await;
        Ok(current_value)
    }

    pub async fn get_inclusion_multi_proof(
        &self,
        indexes_to_prove: Vec<usize>,
    ) -> Result<Vec<String>> {
        let tree_depth = self.get_tree_depth();

        let mut proof: IndexMap<String, bool> = indexes_to_prove
            .iter()
            .map(|&idx| (format!("{}:{}", tree_depth, idx), false))
            .collect();

        let mut current_level = proof.clone();
        for curr_depth in (1..=tree_depth).rev() {
            let mut next_level = IndexMap::new();

            let mut ordered_proof_keys = Vec::new();
            for (index, _) in &current_level {
                let key = format!("{}:{}", tree_depth, index);
                if proof.contains_key(&key) {
                    ordered_proof_keys.push(key);
                }
            }

            for kv in current_level.keys() {
                let kv_parts: Vec<&str> = kv.split(':').collect();
                let current_node_idx = kv_parts[1].parse::<usize>().expect("Invalid index");
                let child_idx = current_node_idx / 2;

                if next_level.contains_key(&format!("{}:{}", curr_depth - 1, child_idx)) {
                    continue;
                }

                let neighbour_idx = if current_node_idx % 2 == 0 {
                    current_node_idx + 1
                } else {
                    current_node_idx - 1
                };

                if !proof.contains_key(&format!("{}:{}", curr_depth, neighbour_idx)) {
                    proof.insert(format!("{}:{}", curr_depth, neighbour_idx), true);
                }

                next_level.insert(format!("{}:{}", curr_depth - 1, child_idx), false);
            }
            next_level.iter().for_each(|(k, v)| {
                proof.insert(k.to_string(), *v);
            });

            current_level = next_level;
        }

        let kv_entries: Vec<SubKey> = proof
            .iter()
            .filter_map(|(kv, &is_needed)| {
                if is_needed {
                    Some(SubKey::String(kv.to_string()))
                } else {
                    None
                }
            })
            .collect();

        let nodes_hash_map = self.nodes.get_many(kv_entries.clone()).await;

        let mut nodes_values: Vec<String> = Vec::with_capacity(kv_entries.len());
        for kv in kv_entries {
            if let Some(node) = nodes_hash_map.get(&kv.to_string()) {
                nodes_values.push(node.to_string());
            }
        }

        Ok(nodes_values)
    }

    pub async fn verify_multi_proof(
        &self,
        indexes: &mut Vec<usize>,
        values: &mut Vec<String>,
        proof: &mut Vec<String>,
    ) -> bool {
        let root = self.root_hash.get(SubKey::None).await.unwrap();
        let calculated_root = self
            .calculate_multiproof_root_hash(indexes, values, proof)
            .unwrap();

        root == calculated_root
    }

    fn calculate_multiproof_root_hash(
        &self,
        indexes: &mut Vec<usize>,
        values: &mut Vec<String>,
        proof: &mut Vec<String>,
    ) -> Result<String> {
        let mut new_indexes = Vec::new();
        let mut new_values = Vec::new();

        while !indexes.is_empty() {
            let index = indexes.remove(0);
            let value = values.remove(0);
            let is_even = index % 2 == 0;
            let wanted_index = if is_even { index + 1 } else { index - 1 };
            let wanted_value_position = indexes.iter().position(|&x| x == wanted_index);

            let wanted_value = match wanted_value_position {
                Some(pos) => {
                    indexes.remove(pos);
                    values.remove(pos)
                }
                None => proof.remove(0),
            };

            if wanted_value.is_empty() {
                return Err(anyhow!("Wanted value not found"));
            }

            let hash = if is_even {
                self.hasher.hash(vec![value, wanted_value])?
            } else {
                self.hasher.hash(vec![wanted_value, value])?
            };

            new_indexes.push(index / 2);

            new_values.push(hash);
        }

        if !proof.is_empty() || new_indexes.len() > 1 {
            return self.calculate_multiproof_root_hash(&mut new_indexes, &mut new_values, proof);
        }

        new_values
            .pop()
            .ok_or_else(|| anyhow!("No root hash found".to_string()))
    }

    fn get_tree_depth(&self) -> usize {
        (self.size as f64).log2().ceil() as usize
    }

    fn render_empty_tree(&self) -> Vec<Vec<Node>> {
        let mut current_height_nodes_count = self.size;
        let mut current_depth = self.get_tree_depth();
        let mut tree: Vec<Vec<Node>> = vec![(0..self.size)
            .map(|index| Node {
                hash: self.null_value.to_string(),
                index,
                depth: current_depth,
            })
            .collect()];
        while current_height_nodes_count > 1 {
            current_depth -= 1;
            let current_height_nodes = tree.last().unwrap();
            let mut next_height_nodes = Vec::new();

            for i in (0..current_height_nodes_count).step_by(2) {
                let left_sibling = &current_height_nodes[i].hash;
                let right_sibling = current_height_nodes
                    .get(i + 1)
                    .map_or(self.null_value.to_string(), |node| node.hash.clone());

                let node = Node {
                    hash: self
                        .hasher
                        .hash(vec![left_sibling.to_string(), right_sibling.to_string()])
                        .unwrap(),
                    index: i / 2,
                    depth: current_depth,
                };

                next_height_nodes.push(node);
            }
            current_height_nodes_count = next_height_nodes.len();
            tree.push(next_height_nodes);
        }
        tree
    }
}
