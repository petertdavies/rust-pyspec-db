pub mod util;
pub mod walk;

use ethereum_types::{H160, H256, U256};
use lmdb::{
    Database, DatabaseFlags, Environment, RwCursor, RwTransaction, Transaction, WriteFlags,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};

use crate::util::{
    cursor_clear_prefix, cursor_delete, cursor_dump_db, get_internal_key, keccak256,
};
use crate::walk::Walker;

static DB_VERSION: &[u8] = b"2";

#[derive(Debug, Clone, PartialEq, Eq)]
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
            destroyed_storage: HashSet::new(),
        })
    }
}

pub struct MutableTransaction<'db> {
    db: Database,
    txn: RwTransaction<'db>,
    accounts: HashMap<H160, Option<Account>>,
    storage: HashMap<H160, HashMap<H256, U256>>,
    destroyed_storage: HashSet<H160>,
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
            let mut db_key = vec![1];
            db_key.extend_from_slice(&get_internal_key(address));
            match self.txn.get(self.db, &db_key) {
                Ok(bytes) => Ok(Some(rlp::decode(bytes)?)),
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
                "Attempted to set storage on non-existent account {:?}",
                address
            );
            self.set_account(address, account);
            let mut map = HashMap::new();
            map.insert(key, value);
            self.storage.insert(address, map);
            Ok(())
        }
    }

    pub fn get_storage(&self, address: H160, key: H256) -> anyhow::Result<U256> {
        if let Some(map) = self.storage.get(&address) {
            if let Some(val) = map.get(&key) {
                return Ok(*val);
            }
        }
        let mut db_key = vec![1];
        db_key.extend_from_slice(address.as_bytes());
        db_key.extend_from_slice(b"\x00");
        db_key.extend_from_slice(key.as_bytes());
        match self.txn.get(self.db, &db_key) {
            Ok(bytes) => Ok(rlp::decode(bytes)?),
            Err(lmdb::Error::NotFound) => Ok(U256::zero()),
            Err(err) => Err(err)?,
        }
    }

    pub fn destroy_storage(&mut self, address: H160) {
        self.destroyed_storage.insert(address);
        self.storage.remove(&address);
    }

    pub fn state_root(&mut self) -> anyhow::Result<H256> {
        {
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
                        None => cursor_delete(&mut cursor, key)?,
                    }
                }

                for address in self.destroyed_storage.iter() {
                    let mut db_prefix = Vec::new();
                    db_prefix.push(1);
                    db_prefix.extend_from_slice(address.as_bytes());
                    db_prefix.push(0);
                    cursor_clear_prefix(&mut cursor, &db_prefix)?;
                    db_prefix.clear();
                    db_prefix.push(2);
                    db_prefix.extend_from_slice(&get_internal_key(address));
                    db_prefix.push(0);
                    cursor_clear_prefix(&mut cursor, &db_prefix)?;
                }

                for (address, map) in self.storage.iter() {
                    for (key, value) in map.iter() {
                        let mut db_key: Vec<u8> = Vec::new();
                        db_key.extend_from_slice(b"\x01");
                        db_key.extend_from_slice(address.as_bytes());
                        db_key.extend_from_slice(b"\x00");
                        db_key.extend_from_slice(key.as_bytes());
                        if value.is_zero() {
                            cursor_delete(&mut cursor, db_key)?
                        } else {
                            cursor.put(&db_key, &rlp::encode(value), WriteFlags::empty())?;
                        }
                    }
                }
            }

            let mut dirty_list = Vec::new();
            for (address, account) in std::mem::take(&mut self.accounts) {
                let internal_address = get_internal_key(address);
                if let Some(account) = account {
                    let mut s = RlpStream::new_list(4);
                    s.append(&account.nonce)
                        .append(&account.balance)
                        .append(&self.storage_root(&address)?)
                        .append(&keccak256(&account.code));
                    dirty_list.push((internal_address, Some(SmallVec::from_slice(&s.out()))));
                } else {
                    dirty_list.push((internal_address, None));
                }
            }
            dirty_list.sort_unstable_by(|x, y| y.0.cmp(&x.0));

            let mut cursor = self.txn.open_rw_cursor(self.db)?;
            let mut walker: Walker = Walker::new(std::slice::from_ref(&2), dirty_list, &mut cursor);

            let root = walker.root()?;

            self.accounts = HashMap::new();
            self.storage = HashMap::new();

            Ok(root)
        }
    }

    pub fn storage_root(&mut self, address: &H160) -> anyhow::Result<H256> {
        let storage = self.storage.remove(&address).unwrap_or_default();
        let mut dirty_storage: Vec<([u8; 64], Option<SmallVec<[u8; 36]>>)> = Vec::new();
        for (key, value) in storage.iter() {
            if value.is_zero() {
                dirty_storage.push((get_internal_key(key), None));
            } else {
                dirty_storage.push((
                    get_internal_key(key),
                    Some(SmallVec::from_slice(&rlp::encode(value))),
                ));
            }
        }
        dirty_storage.sort_unstable_by(|x, y| y.0.cmp(&x.0));

        let mut cursor = self.txn.open_rw_cursor(self.db)?;
        let mut trie_prefix = vec![2];
        trie_prefix.extend_from_slice(&get_internal_key(address));
        trie_prefix.push(0);
        let mut walker = Walker::new(&trie_prefix, dirty_storage, &mut cursor);
        walker.root()
    }

    pub fn commit(mut self) -> anyhow::Result<()> {
        self.state_root()?;
        self.txn.commit()?;
        Ok(())
    }

    pub fn debug_dump_db(&mut self) -> anyhow::Result<()> {
        let cursor = self.txn.open_ro_cursor(self.db)?;
        cursor_dump_db(&cursor)?;
        Ok(())
    }
}
