use arrayvec::ArrayVec;
use ethereum_types::H256;
use lmdb::{RwCursor, WriteFlags};
use once_cell::sync::Lazy;
use rlp;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use smallvec::SmallVec;
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
        rest_of_key: ArrayVec<u8, 64>,
        value: SmallVec<[u8; 36]>,
    },
    Extension {
        key_segment: SmallVec<[u8; 16]>,
        subnode: ArrayVec<u8, 32>,
    },
    Branch {
        subnodes: Vec<Option<ArrayVec<u8, 32>>>,
    },
}

impl Encodable for InternalNode {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            InternalNode::Leaf { rest_of_key, value } => s
                .begin_list(2)
                .append(&encode_nibble_list(rest_of_key, true))
                .append(&value.as_slice()),
            InternalNode::Extension {
                key_segment,
                subnode,
            } => s
                .begin_list(2)
                .append(&encode_nibble_list(key_segment, false))
                .append(&subnode.as_slice()),
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
                                s.append(&data.as_slice());
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
                    rest_of_key: ArrayVec::try_from(&*key_segment).unwrap(),
                    value: SmallVec::from_slice(rlp.at(1)?.data()?),
                })
            } else {
                Ok(InternalNode::Extension {
                    key_segment: SmallVec::from_slice(&key_segment),
                    subnode: {
                        let subnode_rlp = rlp.at(1)?;
                        if subnode_rlp.is_data() {
                            ArrayVec::try_from(subnode_rlp.data()?).unwrap()
                        } else {
                            ArrayVec::try_from(subnode_rlp.as_raw()).unwrap()
                        }
                    },
                })
            }
        } else {
            assert_eq!(rlp.item_count()?, 17);
            let mut subnodes = Vec::new();
            for i in 0..16 {
                let vec: ArrayVec<u8, 32> = {
                    let subnode_rlp = rlp.at(i)?;
                    if subnode_rlp.is_data() {
                        ArrayVec::try_from(subnode_rlp.data()?).unwrap()
                    } else {
                        ArrayVec::try_from(subnode_rlp.as_raw()).unwrap()
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
    prefix_len: usize,
    dirty_list: Vec<([u8; 64], Option<SmallVec<[u8; 36]>>)>,
    cursor: &'txn mut RwCursor<'db>,
    buffer: [u8; 128],
}

impl<'db, 'txn> Walker<'db, 'txn> {
    pub fn new(
        trie_prefix: &[u8],
        dirty_list: Vec<([u8; 64], Option<SmallVec<[u8; 36]>>)>,
        cursor: &'txn mut RwCursor<'db>,
    ) -> Self {
        let mut buffer: [u8; 128] = [0; 128];
        buffer[..trie_prefix.len()].copy_from_slice(trie_prefix);
        Walker {
            prefix_len: trie_prefix.len(),
            dirty_list,
            cursor,
            buffer,
        }
    }

    pub fn root(&mut self) -> anyhow::Result<H256> {
        println!("{:?}", std::mem::size_of::<InternalNode>());
        let root_node = self.walk(0)?;
        let root = self.write_node(0, root_node)?;
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

    fn walk(&mut self, depth: usize) -> anyhow::Result<Option<InternalNode>> {
        let node: Option<InternalNode> = self.get_node(depth)?;
        self.walk_node(depth, node)
    }

    fn walk_node(
        &mut self,
        depth: usize,
        mut current_node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        while self.dirty_list.last().map_or(false, |(k, _)| {
            k.starts_with(&self.buffer[self.prefix_len..self.prefix_len + depth])
        }) {
            current_node = match current_node {
                None => self.walk_empty(depth)?,
                Some(InternalNode::Leaf { rest_of_key, value }) => {
                    self.walk_leaf(depth, rest_of_key, value)?
                }
                Some(InternalNode::Extension {
                    key_segment,
                    subnode,
                }) => self.walk_extension(depth, key_segment, subnode)?,
                Some(InternalNode::Branch { subnodes }) => self.walk_branch(depth, subnodes)?,
            }
        }
        Ok(current_node)
    }

    fn walk_empty(&mut self, depth: usize) -> anyhow::Result<Option<InternalNode>> {
        let (key, value) = self.dirty_list.pop().unwrap();
        debug_assert!(key.starts_with(&self.buffer[self.prefix_len..self.prefix_len + depth]));
        Ok(match value {
            None => None,
            Some(value) => Some(InternalNode::Leaf {
                rest_of_key: ArrayVec::try_from(&key[depth..]).unwrap(),
                value,
            }),
        })
    }
    fn walk_leaf(
        &mut self,
        depth: usize,
        rest_of_key: ArrayVec<u8, 64>,
        value: SmallVec<[u8; 36]>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let (key, new_value) = self.dirty_list.last().unwrap().clone();
        debug_assert!(key.starts_with(&self.buffer[self.prefix_len..self.prefix_len + depth]));
        let common_prefix_len = common_prefix(&rest_of_key, &key[depth..]);
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
            self.buffer[self.prefix_len + depth..self.prefix_len + depth + common_prefix_len]
                .copy_from_slice(&key[depth..depth + common_prefix_len]);
            let branch_node = self.make_branch(
                depth + common_prefix_len,
                rest_of_key[common_prefix_len],
                leaf_node,
            )?;
            self.make_extension(depth, common_prefix_len, branch_node)?
        })
    }
    fn walk_extension(
        &mut self,
        depth: usize,
        key_segment: SmallVec<[u8; 16]>,
        subnode: ArrayVec<u8, 32>,
    ) -> anyhow::Result<Option<InternalNode>> {
        debug_assert_ne!(key_segment.len(), 0);
        self.buffer[self.prefix_len + depth..self.prefix_len + depth + key_segment.len()]
            .copy_from_slice(&key_segment);
        let (key, _) = self.dirty_list.last().unwrap().clone();
        debug_assert!(key.starts_with(&self.buffer[self.prefix_len..self.prefix_len + depth]));
        let common_prefix_len = common_prefix(&key_segment, &key[depth..]);
        if common_prefix_len == key_segment.len() {
            let new_subnode = self.walk(depth + key_segment.len())?;
            return self.make_extension(depth, key_segment.len(), new_subnode);
        }
        let (segment1_len, index, segment2_len) = (
            common_prefix_len,
            key_segment[common_prefix_len],
            key_segment.len() - common_prefix_len - 1,
        );
        let branch_node = if segment2_len == 0 {
            let mut subnodes = vec![None; 16];
            subnodes[index as usize] = Some(subnode);
            self.walk_branch(depth + common_prefix_len, subnodes)?
        } else {
            let extension_node = Some(InternalNode::Extension {
                key_segment: SmallVec::from_slice(&key_segment[common_prefix_len + 1..]),
                subnode,
            });
            self.make_branch(depth + common_prefix_len, index, extension_node)?
        };
        self.make_extension(depth, segment1_len, branch_node)
    }

    fn walk_branch(
        &mut self,
        depth: usize,
        mut subnodes: Vec<Option<ArrayVec<u8, 32>>>,
    ) -> anyhow::Result<Option<InternalNode>> {
        self.buffer[self.prefix_len + depth] = 0;
        while self.dirty_list.last().map_or(false, |(k, _)| {
            k.starts_with(&self.buffer[self.prefix_len..self.prefix_len + depth])
        }) {
            let (key, _) = self.dirty_list.last().unwrap();
            let index = key[depth];
            self.buffer[self.prefix_len + depth] = index;
            let subnode = self.walk(depth + 1)?;
            subnodes[index as usize] = self.write_node(depth + 1, subnode)?;
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
            self.buffer[self.prefix_len + depth] = subnode_index;
            self.make_extension(depth, 1, self.get_node(depth + 1)?)?
        } else {
            Some(InternalNode::Branch { subnodes })
        })
    }

    fn make_branch(
        &mut self,
        depth: usize,
        index: u8,
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        let mut subnodes = vec![None; 16];
        self.buffer[self.prefix_len + depth] = index;
        subnodes[index as usize] = self.write_node(depth + 1, node)?;
        self.walk_branch(depth, subnodes)
    }

    fn make_extension(
        &mut self,
        depth: usize,
        segment_len: usize,
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<InternalNode>> {
        if segment_len == 0 {
            return Ok(node);
        }
        Ok(match node {
            None => {
                self.write_node(depth + segment_len, None)?;
                None
            }
            Some(InternalNode::Leaf { rest_of_key, value }) => {
                self.write_node(depth + segment_len, None)?;
                let mut new_rest_of_key = ArrayVec::try_from(
                    &self.buffer[self.prefix_len + depth..self.prefix_len + depth + segment_len],
                )
                .unwrap();
                new_rest_of_key.try_extend_from_slice(&rest_of_key).unwrap();
                Some(InternalNode::Leaf {
                    rest_of_key: new_rest_of_key,
                    value,
                })
            }
            Some(InternalNode::Extension {
                key_segment,
                subnode,
            }) => {
                self.write_node(depth + segment_len, None)?;
                let mut new_segment = SmallVec::from_slice(
                    &self.buffer[self.prefix_len + depth..self.prefix_len + depth + segment_len],
                );
                new_segment.extend_from_slice(&key_segment);
                Some(InternalNode::Extension {
                    key_segment: new_segment,
                    subnode,
                })
            }
            Some(branch_node @ InternalNode::Branch { .. }) => Some(InternalNode::Extension {
                key_segment: SmallVec::from_slice(
                    &self.buffer[self.prefix_len + depth..self.prefix_len + depth + segment_len],
                ),
                subnode: self
                    .write_node(depth + segment_len, Some(branch_node))?
                    .unwrap(),
            }),
        })
    }

    fn get_node(&self, depth: usize) -> anyhow::Result<Option<InternalNode>> {
        cursor_get(self.cursor, &self.buffer[..self.prefix_len + depth])?
            .map(rlp::decode)
            .transpose()
            .map_err(anyhow::Error::new)
    }

    fn write_node(
        &mut self,
        depth: usize,
        node: Option<InternalNode>,
    ) -> anyhow::Result<Option<ArrayVec<u8, 32>>> {
        Ok(match node {
            None => {
                cursor_delete(self.cursor, &self.buffer[..self.prefix_len + depth])?;
                None
            }
            Some(node) => {
                let node_encoding = rlp::encode(&node);
                self.cursor.put(
                    &&self.buffer[..self.prefix_len + depth],
                    &node_encoding,
                    WriteFlags::empty(),
                )?;
                if node_encoding.len() < 32 {
                    Some(ArrayVec::try_from(&*node_encoding).unwrap())
                } else {
                    Some(ArrayVec::try_from(&*Keccak256::digest(node_encoding)).unwrap())
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
