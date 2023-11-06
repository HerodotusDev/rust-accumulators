use anyhow::Result;
use std::{collections::HashMap, rc::Rc};

use uuid::Uuid;

use crate::{
    hasher::Hasher,
    store::{table::InStoreTable, Store},
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

pub struct IncrementalMerkleTree<S, H> {
    pub store: Rc<S>,
    pub mmr_id: String,
    pub nodes: InStoreTable<S>,
    pub root_hash: InStoreTable<S>,
    pub hasher: H,
    pub size: usize,
    pub null_value: String,
}

impl<S, H> IncrementalMerkleTree<S, H>
where
    S: Store,
    H: Hasher,
{
    fn new(size: usize, null_value: String, hasher: H, store: S, mmr_id: Option<String>) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let root_hash_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::RootHash);
        let nodes_key = format!("{}:nodes:", mmr_id);

        let store_rc = Rc::new(store);
        let root_hash = InStoreTable::new(store_rc.clone(), root_hash_key);
        let nodes = InStoreTable::new(store_rc.clone(), nodes_key);

        Self {
            store: store_rc,
            mmr_id,
            nodes,
            root_hash,
            hasher,
            size,
            null_value,
        }
    }

    pub fn initialize(
        size: usize,
        null_value: String,
        hasher: H,
        store: S,
        mmr_id: Option<String>,
    ) -> Self {
        let tree = IncrementalMerkleTree::new(size, null_value, hasher, store, mmr_id);
        let nodes = tree.render_empty_tree();
        let nodes_hashmap: HashMap<String, String> =
            nodes
                .iter()
                .flatten()
                .fold(HashMap::new(), |mut acc, curr| {
                    let key = format!("{}:{}", curr.depth, curr.index);
                    acc.insert(key, curr.hash.clone());
                    acc
                });

        tree.nodes.set_many(nodes_hashmap);

        tree.root_hash
            .set::<String>(&nodes[nodes.len() - 1][0].hash, None);
        tree
    }

    pub fn get_root(&self) -> String {
        self.root_hash.get::<String>(None).unwrap()
    }

    pub fn get_inclusion_proof(&self, index: usize) -> Result<Vec<String>> {
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

        let kv_entries: Vec<String> = required_nodes_by_height
            .iter()
            .map(|(height, index)| format!("{}:{}", height, index))
            .collect();

        let nodes_hash_map = self.nodes.get_many(kv_entries);

        let mut ordered_nodes = Vec::with_capacity(required_nodes_by_height.len());
        for (height, index) in required_nodes_by_height {
            if let Some(node) = nodes_hash_map.get(&format!("{}:{}", height, index)) {
                ordered_nodes.push(node.clone());
            }
        }
        Ok(ordered_nodes)
    }

    pub fn verify_proof(&self, index: usize, value: &str, proof: Vec<String>) -> Result<bool> {
        let mut current_index = index;
        let mut current_value = value.to_string();

        for p in proof {
            let is_current_index_even = current_index % 2 == 0;
            current_value = if is_current_index_even {
                self.hasher
                    .hash(vec![current_value.to_string(), p])
                    .unwrap()
            } else {
                self.hasher
                    .hash(vec![p, current_value.to_string()])
                    .unwrap()
            };
            current_index /= 2;
        }

        let root = self.root_hash.get::<String>(None).unwrap();
        Ok(root == current_value)
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
