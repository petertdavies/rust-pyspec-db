use ethereum_types::H256;
use lmdb::{RwCursor, WriteFlags};
use once_cell::sync::Lazy;
use rlp;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use std::str::FromStr;
use std::vec::Vec;

use crate::util::{
    common_prefix, cursor_delete, cursor_get, decode_nibble_list, encode_nibble_list, keccak256,
};

pub static EMPTY_TRIE_ROOT: Lazy<H256> = Lazy::new(|| {
    H256::from_str("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").unwrap()
});

#[derive(Debug, Clone)]
enum InternalNode {
    Leaf {
        rest_of_key: Vec<u8>,
        value: Vec<u8>,
    },
    Extension {
        key_segment: Vec<u8>,
        subnode: Vec<u8>,
    },
    Branch {
        subnodes: Vec<Option<Vec<u8>>>,
    },
}

impl Encodable for InternalNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            InternalNode::Leaf { rest_of_key, value } => s
                .begin_list(2)
                .append(&encode_nibble_list(rest_of_key, true))
                .append(value),
            InternalNode::Extension {
                key_segment,
                subnode,
            } => s
                .begin_list(2)
                .append(&encode_nibble_list(key_segment, false))
                .append(subnode),
            InternalNode::Branch { subnodes } => {
                s.begin_list(17);
                for subnode in subnodes {
                    match subnode {
                        None => {
                            s.append_empty_data();
                        }
                        Some(data) => {
                            if data.len() < 32 {
                                s.append_raw(data, 1);
                            } else {
                                s.append(data);
                            }
                        }
                    };
                }
                s.append_empty_data()
            }
        };
    }
}

impl Decodable for InternalNode {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        if rlp.item_count()? == 2 {
            let (key_segment, is_leaf) = decode_nibble_list(rlp.at(0)?.data()?);
            if is_leaf {
                Ok(InternalNode::Leaf {
                    rest_of_key: key_segment,
                    value: rlp.val_at(1)?,
                })
            } else {
                Ok(InternalNode::Extension {
                    key_segment,
                    subnode: {
                        let subnode_rlp = rlp.at(1)?;
                        if subnode_rlp.is_data() {
                            subnode_rlp.data()?.to_vec()
                        } else {
                            subnode_rlp.as_raw().to_vec()
                        }
                    },
                })
            }
        } else {
            assert_eq!(rlp.item_count()?, 17);
            let mut subnodes = Vec::new();
            for i in 0..16 {
                let vec: Vec<u8> = {
                    let subnode_rlp = rlp.at(i)?;
                    if subnode_rlp.is_data() {
                        subnode_rlp.data()?.to_vec()
                    } else {
                        subnode_rlp.as_raw().to_vec()
                    }
                };
                if vec.len() == 0 {
                    subnodes.push(None);
                } else {
                    subnodes.push(Some(vec))
                }
            }
            Ok(InternalNode::Branch { subnodes })
        }
    }
}

pub struct Walker<'db, 'txn> {
    pub trie_prefix: Vec<u8>,
    pub dirty_list: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    pub cursor: &'txn mut RwCursor<'db>,
}

impl<'db, 'txn> Walker<'db, 'txn> {
    pub fn root(&mut self) -> anyhow::Result<H256> {
        let root_node = self.walk(&[])?;
        let root = self.write_node(&[], root_node)?;
        Ok(match root {
            Some(root) => {
                if root.len() < 32 {
                    keccak256(root)
                } else {
                    H256::from_slice(&root)
                }
            }
            None => *EMPTY_TRIE_ROOT,
        })
    }

    fn walk(&mut self, node_prefix: &[u8]) -> anyhow::Result<Option<InternalNode>> {
        let node: Option<InternalNode> = self.get_node(node_prefix)?;
        self.walk_node(node_prefix, node)
    }

    fn walk_node(
        &mut self,
        node_prefix: &[u8],
        mut current_node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        while self
            .dirty_list
            .last()
            .map_or(false, |(k, _)| k.starts_with(node_prefix))
        {
            current_node = match current_node {
                None => self.walk_empty(node_prefix)?,
                Some(InternalNode::Leaf { rest_of_key, value }) => {
                    self.walk_leaf(node_prefix, rest_of_key, value)?
                }
                Some(InternalNode::Extension {
                    key_segment,
                    subnode,
                }) => self.walk_extension(node_prefix, key_segment, subnode)?,
                Some(InternalNode::Branch { subnodes }) => {
                    self.walk_branch(node_prefix, subnodes)?
                }
            }
        }
        Ok(current_node)
    }

    fn walk_empty(&mut self, node_prefix: &[u8]) -> anyhow::Result<Option<InternalNode>> {
        let (key, value) = self.dirty_list.pop().unwrap();
        debug_assert!(key.starts_with(node_prefix));
        Ok(match value {
            None => None,
            Some(value) => Some(InternalNode::Leaf {
                rest_of_key: key[node_prefix.len()..].to_vec(),
                value,
            }),
        })
    }
    fn walk_leaf(
        &mut self,
        node_prefix: &[u8],
        rest_of_key: Vec<u8>,
        value: Vec<u8>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let (key, new_value) = self.dirty_list.last().unwrap().clone();
        debug_assert!(key.starts_with(node_prefix));
        let common_prefix_len = common_prefix(&rest_of_key, &key[node_prefix.len()..]);
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
                rest_of_key: rest_of_key[common_prefix_len + 1..].to_vec(),
                value,
            });
            let branch_node = self.make_branch(
                &key[..node_prefix.len() + common_prefix_len],
                rest_of_key[common_prefix_len],
                leaf_node,
            )?;
            self.make_extension(node_prefix, &rest_of_key[..common_prefix_len], branch_node)?
        })
    }
    fn walk_extension(
        &mut self,
        node_prefix: &[u8],
        key_segment: Vec<u8>,
        subnode: Vec<u8>,
    ) -> anyhow::Result<Option<InternalNode>> {
        assert_ne!(key_segment.len(), 0);
        let (key, _) = self.dirty_list.last().unwrap().clone();
        debug_assert!(key.starts_with(node_prefix));
        let common_prefix_len = common_prefix(&key_segment, &key[node_prefix.len()..]);
        if common_prefix_len == key_segment.len() {
            let new_subnode = self.walk(&key[..node_prefix.len() + key_segment.len()])?;
            return self.make_extension(node_prefix, &key_segment, new_subnode);
        }
        let (segment1, index, segment2) = (
            &key_segment[..common_prefix_len],
            key_segment[common_prefix_len],
            &key_segment[common_prefix_len + 1..],
        );
        let branch_node = if segment2.len() == 0 {
            let mut subnodes = vec![None; 16];
            subnodes[index as usize] = Some(subnode);
            self.walk_branch(&key[..node_prefix.len() + common_prefix_len], subnodes)?
        } else {
            let extension_node = Some(InternalNode::Extension {
                key_segment: segment2.to_vec(),
                subnode,
            });
            self.make_branch(
                &key[..node_prefix.len() + common_prefix_len],
                index,
                extension_node,
            )?
        };
        self.make_extension(node_prefix, segment1, branch_node)
    }

    fn walk_branch(
        &mut self,
        node_prefix: &[u8],
        mut subnodes: Vec<Option<Vec<u8>>>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let mut prefix = node_prefix.to_vec();
        prefix.push(0);
        while self
            .dirty_list
            .last()
            .map_or(false, |(k, _)| k.starts_with(node_prefix))
        {
            let (key, _) = self.dirty_list.last().unwrap();
            let index = key[node_prefix.len()];
            prefix[node_prefix.len()] = index;
            let subnode = self.walk(&prefix)?;
            subnodes[index as usize] = self.write_node(&prefix, subnode)?;
        }

        let mut num_subnodes = 0;
        let mut subnode_index: u8 = 0;
        for (i, subnode) in subnodes.iter().enumerate() {
            if subnode.is_some() {
                num_subnodes += 1;
                subnode_index = i as u8;
            }
        }
        Ok(if num_subnodes == 0 {
            None
        } else if num_subnodes == 1 {
            let mut key = node_prefix.to_vec();
            key.push(subnode_index);
            self.make_extension(
                node_prefix,
                std::slice::from_ref(&subnode_index),
                self.get_node(&key)?,
            )?
        } else {
            Some(InternalNode::Branch { subnodes })
        })
    }
    fn make_branch(
        &mut self,
        node_prefix: &[u8],
        index: u8,
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let mut subnodes = vec![None; 16];
        let mut subnode_prefix = node_prefix.to_vec();
        subnode_prefix.push(index);
        subnodes[index as usize] = self.write_node(&subnode_prefix, node)?;
        self.walk_branch(node_prefix, subnodes)
    }

    fn make_extension(
        &mut self,
        source: &[u8],
        segment: &[u8],
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        if segment.len() == 0 {
            return Ok(node);
        }
        let mut target = source.to_vec();
        target.extend_from_slice(segment);
        Ok(match node {
            None => {
                self.write_node(&target, None)?;
                None
            }
            Some(InternalNode::Leaf { rest_of_key, value }) => {
                self.write_node(&target, None)?;
                let mut new_rest_of_key = segment.to_vec();
                new_rest_of_key.extend_from_slice(&rest_of_key);
                Some(InternalNode::Leaf {
                    rest_of_key: new_rest_of_key,
                    value,
                })
            }
            Some(InternalNode::Extension {
                key_segment,
                subnode,
            }) => {
                self.write_node(&target, None)?;
                let mut new_segment = segment.to_vec();
                new_segment.extend_from_slice(&key_segment);
                Some(InternalNode::Extension {
                    key_segment: new_segment,
                    subnode,
                })
            }
            Some(branch_node @ InternalNode::Branch { .. }) => Some(InternalNode::Extension {
                key_segment: segment.to_vec(),
                subnode: self.write_node(&target, Some(branch_node))?.unwrap(),
            }),
        })
    }

    fn get_node(&self, node_prefix: &[u8]) -> anyhow::Result<Option<InternalNode>> {
        let mut key = self.trie_prefix.to_vec();
        key.extend(node_prefix);
        cursor_get(self.cursor, key)?
            .map(rlp::decode)
            .transpose()
            .map_err(anyhow::Error::new)
    }

    fn write_node(
        &mut self,
        node_prefix: &[u8],
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let mut key = self.trie_prefix.clone();
        key.extend_from_slice(node_prefix);
        Ok(match node {
            None => {
                cursor_delete(self.cursor, key)?;
                None
            }
            Some(node) => {
                let node_encoding = rlp::encode(&node);
                self.cursor.put(&key, &node_encoding, WriteFlags::empty())?;
                if node_encoding.len() < 32 {
                    Some(node_encoding.to_vec())
                } else {
                    Some(Keccak256::digest(node_encoding).to_vec())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_nibble_list() {
        assert_eq!(encode_nibble_list(&[1, 2, 3], true), vec![49, 35]);
        assert_eq!(encode_nibble_list(&[1, 2, 3], false), vec![17, 35]);
        assert_eq!(encode_nibble_list(&[1, 2, 3, 4], true), vec![32, 18, 52]);
        assert_eq!(encode_nibble_list(&[1, 2, 3, 4], false), vec![0, 18, 52]);
        assert_eq!((vec![1, 2, 3], true), decode_nibble_list(&[49, 35]));
        assert_eq!((vec![1, 2, 3], false), decode_nibble_list(&[17, 35]));
        assert_eq!((vec![1, 2, 3, 4], true), decode_nibble_list(&[32, 18, 52]));
        assert_eq!((vec![1, 2, 3, 4], false), decode_nibble_list(&[0, 18, 52]));
    }
}
