use arrayvec::ArrayVec;
use ethereum_types::H256;
use once_cell::sync::Lazy;
use smallvec::SmallVec;
use std::str::FromStr;
use std::vec::Vec;

use crate::backend::BackendTransaction;
use crate::structs::{nibble_list_to_key, InternalNode, NibbleList};
use crate::util::{common_prefix, keccak256};

pub static EMPTY_TRIE_ROOT: Lazy<H256> = Lazy::new(|| {
    H256::from_str("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap()
});

pub struct Walker<'db, 'txn, 'a> {
    prefix: &'a [u8],
    dirty_list: Vec<(NibbleList, Option<SmallVec<[u8; 36]>>)>,
    tx: &'txn mut BackendTransaction<'db>,
    nibble_list: NibbleList,
}

impl<'db, 'txn, 'a> Walker<'db, 'txn, 'a> {
    pub fn new(
        trie_prefix: &'a [u8],
        dirty_list: Vec<(NibbleList, Option<SmallVec<[u8; 36]>>)>,
        tx: &'txn mut BackendTransaction<'db>,
    ) -> Self {
        Walker {
            prefix: trie_prefix,
            dirty_list,
            tx,
            nibble_list: NibbleList::new(),
        }
    }

    pub fn root(&mut self) -> anyhow::Result<H256> {
        let root_node = self.walk()?;
        let root = self.write_node(root_node)?;
        Ok(if root.is_empty() {
            *EMPTY_TRIE_ROOT
        } else {
            if root.len() < 32 {
                keccak256(root)
            } else {
                H256::from_slice(&root)
            }
        })
    }

    fn walk(&mut self) -> anyhow::Result<Option<InternalNode>> {
        let node: Option<InternalNode> = self.get_node()?;
        self.walk_node(node)
    }

    fn walk_node(
        &mut self,
        mut current_node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        while self
            .dirty_list
            .last()
            .map_or(false, |(k, _)| k.starts_with(&self.nibble_list))
        {
            current_node = match current_node {
                None => self.walk_empty()?,
                Some(InternalNode::Leaf { rest_of_key, value }) => {
                    self.walk_leaf(rest_of_key, value)?
                }
                Some(InternalNode::Branch {
                    extension_nibbles,
                    subnodes,
                }) => self.walk_branch(extension_nibbles, subnodes)?,
            }
        }
        Ok(current_node)
    }

    fn walk_empty(&mut self) -> anyhow::Result<Option<InternalNode>> {
        let (key, value) = self.dirty_list.pop().unwrap();
        debug_assert!(key.starts_with(&self.nibble_list));
        Ok(match value {
            None => None,
            Some(value) => Some(InternalNode::Leaf {
                rest_of_key: ArrayVec::try_from(&key[self.nibble_list.len()..]).unwrap(),
                value,
            }),
        })
    }

    fn walk_leaf(
        &mut self,
        rest_of_key: ArrayVec<u8, 64>,
        value: SmallVec<[u8; 36]>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let (key, new_value) = self.dirty_list.last().unwrap().clone();
        debug_assert!(key.starts_with(&self.nibble_list));
        let common_prefix_len = common_prefix(&rest_of_key, &key[self.nibble_list.len()..]);
        Ok(if common_prefix_len == rest_of_key.len() {
            // Both keys are the same
            self.dirty_list.pop();
            match new_value {
                None => None,
                Some(new_value) => Some(InternalNode::Leaf {
                    rest_of_key,
                    value: new_value,
                }),
            }
        } else {
            let leaf_node = Some(InternalNode::Leaf {
                rest_of_key: ArrayVec::try_from(&rest_of_key[common_prefix_len + 1..]).unwrap(),
                value,
            });
            self.make_branch(
                NibbleList::try_from(&rest_of_key[..common_prefix_len])?,
                rest_of_key[common_prefix_len],
                leaf_node,
            )?
        })
    }

    fn split_extension(
        &mut self,
        extension_nibbles: NibbleList,
        subnodes: [ArrayVec<u8, 32>; 16],
    ) -> anyhow::Result<Option<InternalNode>> {
        let common_prefix_length = common_prefix(
            &extension_nibbles,
            &self.dirty_list.last().unwrap().0[self.nibble_list.len()..],
        );
        let (segment0, index, segment1) = (
            &extension_nibbles[..common_prefix_length],
            extension_nibbles[common_prefix_length],
            &extension_nibbles[common_prefix_length + 1..],
        );
        let branch_node = Some(InternalNode::Branch {
            extension_nibbles: NibbleList::try_from(segment1)?,
            subnodes,
        });
        self.make_branch(NibbleList::try_from(segment0)?, index, branch_node)
    }

    fn raise_subnode(
        &mut self,
        mut extension_nibbles: NibbleList,
        subnode_index: u8,
    ) -> anyhow::Result<Option<InternalNode>> {
        extension_nibbles.push(subnode_index);
        self.nibble_list.try_extend_from_slice(&extension_nibbles)?;
        let subnode = self.get_node()?;
        self.write_node(None)?;
        self.nibble_list
            .truncate(self.nibble_list.len() - extension_nibbles.len());
        Ok(match subnode {
            None => unreachable!(),
            Some(InternalNode::Leaf { rest_of_key, value }) => {
                extension_nibbles.try_extend_from_slice(&rest_of_key)?;
                Some(InternalNode::Leaf {
                    rest_of_key: extension_nibbles,
                    value,
                })
            }
            Some(InternalNode::Branch {
                extension_nibbles: extension_nibbles1,
                subnodes,
            }) => {
                extension_nibbles.try_extend_from_slice(&extension_nibbles1)?;
                Some(InternalNode::Branch {
                    extension_nibbles,
                    subnodes,
                })
            }
        })
    }

    fn walk_branch(
        &mut self,
        extension_nibbles: NibbleList,
        mut subnodes: [ArrayVec<u8, 32>; 16],
    ) -> anyhow::Result<Option<InternalNode>> {
        if self.dirty_list.last().map_or(false, |(k, _)| {
            !k[self.nibble_list.len()..].starts_with(extension_nibbles.as_slice())
        }) {
            return self.split_extension(extension_nibbles, subnodes);
        }
        self.nibble_list.try_extend_from_slice(&extension_nibbles)?;
        while self
            .dirty_list
            .last()
            .map_or(false, |(k, _)| k.starts_with(&self.nibble_list))
        {
            let (key, _) = self.dirty_list.last().unwrap();
            let index = key[self.nibble_list.len()];
            self.nibble_list.push(index);
            let subnode = self.walk()?;
            subnodes[index as usize] = self.write_node(subnode)?;
            self.nibble_list.pop();
        }
        self.nibble_list
            .truncate(self.nibble_list.len() - extension_nibbles.len());

        let mut num_subnodes = 0;
        let mut subnode_index: u8 = 0;
        for (i, subnode) in subnodes.iter().enumerate() {
            if !subnode.is_empty() {
                num_subnodes += 1;
                subnode_index = i as u8;
            }
        }
        Ok(if num_subnodes == 0 {
            None
        } else if num_subnodes == 1 {
            self.raise_subnode(extension_nibbles, subnode_index)?
        } else {
            Some(InternalNode::Branch {
                extension_nibbles,
                subnodes,
            })
        })
    }

    fn make_branch(
        &mut self,
        extension_nibbles: NibbleList,
        index: u8,
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let mut subnodes: [ArrayVec<u8, 32>; 16] = Default::default();
        self.nibble_list.try_extend_from_slice(&extension_nibbles)?;
        self.nibble_list.push(index);
        subnodes[index as usize] = self.write_node(node)?;
        self.nibble_list
            .truncate(self.nibble_list.len() - extension_nibbles.len() - 1);
        self.walk_branch(extension_nibbles, subnodes)
    }

    fn get_node(&self) -> anyhow::Result<Option<InternalNode>> {
        let mut db_key = self.prefix.to_vec();
        db_key.extend_from_slice(&nibble_list_to_key(&self.nibble_list));
        Ok(self.tx.get(&db_key)?.map(InternalNode::unmarshal))
    }

    fn write_node(&mut self, node: Option<InternalNode>) -> anyhow::Result<ArrayVec<u8, 32>> {
        if let Some(InternalNode::Branch { subnodes, .. }) = node.clone() {
            assert!(!subnodes.iter().all(|x| x.is_empty()));
        }
        let mut db_key = self.prefix.to_vec();
        db_key.extend_from_slice(&nibble_list_to_key(&self.nibble_list));
        Ok(match node {
            None => {
                self.tx.delete(&db_key)?;
                ArrayVec::new()
            }
            Some(node) => {
                self.tx.put(&db_key, &node.marshal())?;
                node.encode()
            }
        })
    }
}
