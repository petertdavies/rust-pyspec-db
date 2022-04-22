use ethereum_types::{H160, H256, U256};
use lmdb::{
    Cursor, Database, DatabaseFlags, Environment, RwCursor, RwTransaction, Transaction, WriteFlags,
};
use lmdb_sys::MDB_SET_KEY;
use once_cell::sync::Lazy;
use rlp;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::str::FromStr;
use std::vec::Vec;

static DB_VERSION: &[u8] = b"2";

fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(&Keccak256::digest(data.as_ref()))
}

fn common_prefix(xs: &[u8], ys: &[u8]) -> usize {
    xs.iter().zip(ys).take_while(|(x, y)| x == y).count()
}

fn cursor_get<'txn>(
    cursor: &impl Cursor<'txn>,
    key: impl AsRef<[u8]>,
) -> Result<Option<&'txn [u8]>, lmdb::Error> {
    let res = cursor.get(Some(key.as_ref()), None, MDB_SET_KEY);
    match res {
        Ok((_, val)) => Ok(Some(val)),
        Err(lmdb::Error::NotFound) => Ok(None),
        Err(err) => Err(err),
    }
}

fn cursor_delete<'txn>(
    cursor: &impl Cursor<'txn>,
    key: impl AsRef<[u8]>,
) -> Result<(), lmdb::Error> {
    let res = cursor.get(Some(key.as_ref()), None, MDB_SET_KEY);
    match res {
        Ok((_, _)) => Ok(()),
        Err(lmdb::Error::NotFound) => Ok(()),
        Err(err) => Err(err),
    }
}

fn encode_nibble_list(nibble_list: &[u8], is_leaf: bool) -> Vec<u8> {
    let mut res = Vec::new();
    if nibble_list.len() % 2 == 0 {
        res.push(16 * 2 * is_leaf as u8);
        for i in 0..nibble_list.len() / 2 {
            res.push(16 * nibble_list[i * 2] + nibble_list[i * 2 + 1]);
        }
    } else {
        res.push(16 * (2 * (is_leaf as u8) + 1) + nibble_list[0]);
        for i in 0..nibble_list.len() / 2 {
            res.push(16 * nibble_list[i * 2 + 1] + nibble_list[i * 2 + 2]);
        }
    }
    res
}

fn decode_nibble_list(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut res = Vec::new();
    let parity = bytes[0] & 0x10 != 0;
    let is_leaf = bytes[0] & 0x20 != 0;
    if parity {
        res.push(bytes[0] & 0x0F);
    }
    for i in 1..bytes.len() {
        res.push(bytes[i] >> 4);
        res.push(bytes[i] & 0x0F);
    }
    (res, is_leaf)
}

fn get_internal_key(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    let hash = keccak256(bytes);
    let mut res = Vec::new();
    for byte in hash.as_bytes() {
        res.push(byte >> 4);
        res.push(byte & 0x0F);
    }
    res
}

#[derive(Debug, Clone)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub code: Vec<u8>,
}

impl Encodable for Account {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.nonce)
            .append(&self.balance)
            .append(&self.code);
    }
}

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Account {
            nonce: rlp.val_at(0)?,
            balance: rlp.val_at(1)?,
            code: rlp.val_at(2)?,
        })
    }
}

trait Node: Sized + Clone {
    fn make_node(&self, cursor: RwCursor, key: &[u8]) -> anyhow::Result<Vec<u8>>;
}

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

pub struct DB {
    env: lmdb::Environment,
    db: Database,
}

impl DB {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        Self::open_internal(path, true, false)
    }

    pub fn create(path: &std::path::Path, allow_existing: bool) -> anyhow::Result<Self> {
        Self::open_internal(path, allow_existing, true)
    }

    fn open_internal(
        path: &std::path::Path,
        allow_existing: bool,
        create_if_not_existing: bool,
    ) -> anyhow::Result<Self> {
        assert!(allow_existing || create_if_not_existing);
        std::fs::create_dir_all(path)?;
        let env = Environment::new()
            .set_map_size(usize::pow(2, 40))
            .open(path)?;
        let db = if create_if_not_existing {
            env.create_db(None, DatabaseFlags::empty())?
        } else {
            env.open_db(None)?
        };
        let res = DB { env, db };

        let mut tx = res.begin_mutable()?;
        match tx.get_metadata(b"version")? {
            None => anyhow::ensure!(create_if_not_existing, "Database missing version"),
            Some(version) => anyhow::ensure!(
                version == DB_VERSION,
                "Wrong DB_VERSION expected: {:?}, got: {:?}",
                DB_VERSION,
                version,
            ),
        }
        tx.set_metadata(b"version", DB_VERSION)?;
        tx.commit()?;
        Ok(res)
    }

    pub fn begin_mutable<'db>(&'db self) -> anyhow::Result<MutableTransaction<'db>> {
        let txn: lmdb::RwTransaction<'db> = self.env.begin_rw_txn()?;
        Ok(MutableTransaction {
            db: self.db,
            txn,
            accounts: HashMap::new(),
            storage: HashMap::new(),
        })
    }
}

pub struct MutableTransaction<'db> {
    db: Database,
    txn: RwTransaction<'db>,
    accounts: HashMap<H160, Option<Account>>,
    storage: HashMap<H160, HashMap<H256, U256>>,
}

impl<'db> MutableTransaction<'db> {
    pub fn get_metadata(&self, key: &[u8]) -> anyhow::Result<Option<&[u8]>> {
        let mut db_key = vec![0];
        db_key.extend_from_slice(key);
        match self.txn.get(self.db, &db_key) {
            Ok(val) => Ok(Some(val)),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(err) => Err(err)?,
        }
    }

    pub fn set_metadata(&mut self, key: &[u8], val: &[u8]) -> anyhow::Result<()> {
        let mut db_key = vec![0];
        db_key.extend_from_slice(key);
        self.txn.put(self.db, &db_key, &val, WriteFlags::empty())?;
        Ok(())
    }

    pub fn set_account(&mut self, address: H160, account: Option<Account>) {
        self.accounts.insert(address, account);
    }

    pub fn get_account_optional(&mut self, address: H160) -> anyhow::Result<Option<Account>> {
        if let Some(account) = self.accounts.get(&address) {
            Ok(account.clone())
        } else {
            let mut db_key = vec![0];
            db_key.extend_from_slice(&get_internal_key(address));
            match self.txn.get(self.db, &db_key) {
                Ok(bytes) => Ok(rlp::decode(bytes)?),
                Err(lmdb::Error::NotFound) => Ok(None),
                Err(err) => Err(err)?,
            }
        }
    }

    pub fn set_storage(&mut self, address: H160, key: H256, value: U256) -> anyhow::Result<()> {
        if let Some(map) = self.storage.get_mut(&address) {
            map.insert(key, value);
            Ok(())
        } else {
            let account = self.get_account_optional(address)?;
            anyhow::ensure!(
                account.is_some(),
                "Attempted to set storage on non-existent account"
            );
            self.set_account(address, account);
            let mut map = HashMap::new();
            map.insert(key, value);
            self.storage.insert(address, map);
            Ok(())
        }
    }

    pub fn state_root(&mut self) -> anyhow::Result<H256> {
        {
            let mut cursor = self.txn.open_rw_cursor(self.db)?;
            for (address, account) in self.accounts.iter() {
                let mut key: Vec<u8> = Vec::new();
                key.extend_from_slice(b"\x01");
                // The get internal key here is a bug that originated in the Python version
                key.extend_from_slice(&get_internal_key(address));
                match account {
                    Some(account) => {
                        let value = rlp::encode(account);
                        cursor.put(&key, &value, WriteFlags::empty())?;
                    }
                    None => cursor_delete(&cursor, key)?,
                }
            }

            for (address, map) in self.storage.iter() {
                for (key, value) in map.iter() {
                    let mut db_key: Vec<u8> = Vec::new();
                    db_key.extend_from_slice(b"\x01");
                    db_key.extend_from_slice(address.as_bytes());
                    db_key.extend_from_slice(b"\x00");
                    db_key.extend_from_slice(key.as_bytes());
                    if value.is_zero() {
                        cursor_delete(&cursor, db_key)?
                    } else {
                        cursor.put(&db_key, &rlp::encode(value), WriteFlags::empty())?;
                    }
                }
            }

            let mut dirty_storage: HashMap<Vec<u8>, Vec<(Vec<u8>, Option<Vec<u8>>)>> =
                HashMap::new();
            for (address, storage) in self.storage.iter() {
                let vec = dirty_storage.entry(get_internal_key(address)).or_default();
                for (key, value) in storage.iter() {
                    if value.is_zero() {
                        vec.push((get_internal_key(key), None));
                    } else {
                        vec.push((get_internal_key(key), Some(rlp::encode(value).to_vec())));
                    }
                }
                vec.sort_unstable_by(|x, y| y.0.cmp(&x.0))
            }

            let mut dirty_list = Vec::new();
            for (address, account) in &self.accounts {
                let internal_address = get_internal_key(address);
                if let Some(account) = account {
                    let mut trie_prefix = vec![2];
                    trie_prefix.extend_from_slice(&get_internal_key(address));
                    trie_prefix.push(0);
                    let mut walker = Walker {
                        trie_prefix,
                        dirty_list: dirty_storage.remove(&internal_address).unwrap_or_default(),
                        cursor: &mut cursor,
                    };
                    let mut s = RlpStream::new_list(4);
                    s.append(&account.nonce)
                        .append(&account.balance)
                        .append(&walker.root()?)
                        .append(&keccak256(&account.code));
                    dirty_list.push((internal_address, Some(s.out().to_vec())));
                } else {
                    dirty_list.push((internal_address, None));
                }
            }
            dirty_list.sort_unstable_by(|x, y| y.0.cmp(&x.0));

            let mut walker: Walker = Walker {
                trie_prefix: vec![2],
                dirty_list,
                cursor: &mut cursor,
            };

            let root = walker.root()?;

            self.accounts = HashMap::new();
            self.storage = HashMap::new();

            Ok(root)
        }
    }

    pub fn commit(mut self) -> anyhow::Result<()> {
        self.state_root()?;
        self.txn.commit()?;
        Ok(())
    }
}

struct Walker<'db, 'txn> {
    trie_prefix: Vec<u8>,
    dirty_list: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    cursor: &'txn mut RwCursor<'db>,
}

impl<'db, 'txn> Walker<'db, 'txn> {
    fn root(&mut self) -> anyhow::Result<H256> {
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
    use crate::*;
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
