pub mod backend;
pub mod structs;
pub mod util;
pub mod walk;

use ethereum_types::{H160, H256, U256};
use rlp::RlpStream;
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::{remove_dir, remove_file};

use crate::backend::{Backend, BackendTransaction};
pub use crate::structs::Account;
use crate::structs::{get_internal_key, marshal_storage, unmarshal_storage, NibbleList};
pub use crate::util::{keccak256, EMPTY_CODE_HASH};
use crate::walk::Walker;

pub static DB_VERSION: &[u8] = b"0";

pub struct DB {
    backend: Backend,
}

impl DB {
    pub fn open(path: &std::path::Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        let backend = Backend::open(path)?;

        let mut self_ = Self { backend };

        let mut tx = self_.begin_mutable()?;
        match tx.get_metadata(b"version")? {
            None => tx.set_metadata(b"version", DB_VERSION)?,
            Some(version) => anyhow::ensure!(
                version == DB_VERSION,
                "Wrong DB_VERSION expected: {:?}, got: {:?}",
                DB_VERSION,
                version,
            ),
        }
        tx.commit()?;

        Ok(self_)
    }

    pub fn delete_db(path: &std::path::Path) -> anyhow::Result<()> {
        if path.exists() {
            for dir_entry in path.read_dir()? {
                let dir_entry = dir_entry?;
                if ["mdbx.dat", "mdbx.lck"].contains(
                    &dir_entry
                        .path()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .ok_or(anyhow::anyhow!("Failed to decode filename"))?,
                ) {
                    remove_file(dir_entry.path())?;
                } else {
                    anyhow::bail!("Unexpected file in DB: {}", dir_entry.path().display());
                }
            }
            remove_dir(path)?;
        }
        Ok(())
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        Ok(Self {
            backend: Backend::open_in_memory()?,
        })
    }

    pub fn begin_mutable(&mut self) -> anyhow::Result<MutableTransaction<'_>> {
        Ok(MutableTransaction {
            tx: self.backend.begin_mutable()?,
            accounts: HashMap::new(),
            storage: HashMap::new(),
            destroyed_storage: HashSet::new(),
        })
    }
}

pub struct MutableTransaction<'db> {
    tx: BackendTransaction<'db>,
    accounts: HashMap<H160, Option<Account>>,
    storage: HashMap<H160, HashMap<H256, U256>>,
    destroyed_storage: HashSet<H160>,
}

impl<'db> MutableTransaction<'db> {
    pub fn get_metadata(&self, key: &[u8]) -> anyhow::Result<Option<Cow<[u8]>>> {
        let mut db_key = vec![0];
        db_key.extend_from_slice(key);
        self.tx.get(&db_key)
    }

    pub fn set_metadata(&mut self, key: &[u8], val: &[u8]) -> anyhow::Result<()> {
        let mut db_key = vec![0];
        db_key.extend_from_slice(key);
        self.tx.put(&db_key, val)?;
        Ok(())
    }

    pub fn store_code(&mut self, code: &[u8]) -> anyhow::Result<H256> {
        if code.is_empty() {
            return Ok(*EMPTY_CODE_HASH);
        }
        let code_hash = keccak256(code);
        let mut db_key = vec![3];
        db_key.extend_from_slice(code_hash.as_bytes());
        if self.tx.get(&db_key)?.is_none() {
            self.tx.put(&db_key, code)?;
        }
        Ok(code_hash)
    }

    pub fn get_code(&mut self, code_hash: H256) -> anyhow::Result<Option<Cow<[u8]>>> {
        if code_hash == *EMPTY_CODE_HASH {
            return Ok(Some(Cow::Borrowed(&[])));
        }
        let mut db_key = vec![3];
        db_key.extend_from_slice(code_hash.as_bytes());
        self.tx.get(&db_key)
    }

    pub fn set_account(&mut self, address: H160, account: Option<Account>) {
        self.accounts.insert(address, account);
    }

    pub fn get_account_optional(&mut self, address: H160) -> anyhow::Result<Option<Account>> {
        if let Some(account) = self.accounts.get(&address) {
            Ok(account.clone())
        } else {
            let mut db_key = vec![1];
            db_key.extend_from_slice(address.as_bytes());
            match self.tx.get(&db_key)? {
                None => Ok(None),
                Some(data) => Ok(Some(Account::unmarshal(&data))),
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
        db_key.extend_from_slice(key.as_bytes());
        match self.tx.get(&db_key)? {
            None => Ok(U256::zero()),
            Some(data) => Ok(unmarshal_storage(&data)),
        }
    }

    pub fn destroy_storage(&mut self, address: H160) {
        self.destroyed_storage.insert(address);
        self.storage.remove(&address);
    }

    pub fn state_root(&mut self) -> anyhow::Result<H256> {
        {
            {
                for (address, account) in self.accounts.iter() {
                    let mut key: Vec<u8> = vec![1];
                    key.extend_from_slice(address.as_bytes());
                    match account {
                        Some(account) => {
                            self.tx.put(&key, &account.marshal())?;
                        }
                        None => self.tx.delete(&key)?,
                    };
                }

                for address in self.destroyed_storage.iter() {
                    let mut db_prefix = vec![1];
                    db_prefix.extend_from_slice(address.as_bytes());
                    self.tx.clear_prefix(&db_prefix)?;
                    db_prefix.clear();
                    db_prefix.push(2);
                    db_prefix.extend_from_slice(&get_internal_key(address));
                    self.tx.clear_prefix(&db_prefix)?;
                    self.tx.delete(&db_prefix)?;
                }

                for (address, map) in self.storage.iter() {
                    for (key, value) in map.iter() {
                        let mut db_key: Vec<u8> = vec![1];
                        db_key.extend_from_slice(address.as_bytes());
                        db_key.extend_from_slice(key.as_bytes());
                        if value.is_zero() {
                            self.tx.delete(&db_key)?
                        } else {
                            self.tx.put(&db_key, &marshal_storage(*value))?;
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
                        .append(&account.code_hash);
                    dirty_list.push((internal_address, Some(SmallVec::from_slice(&s.out()))));
                } else {
                    dirty_list.push((internal_address, None));
                }
            }
            dirty_list.sort_unstable_by(|x, y| y.0.cmp(&x.0));

            let mut walker: Walker =
                Walker::new(std::slice::from_ref(&2), dirty_list, &mut self.tx);

            let root = walker.root()?;

            self.accounts = HashMap::new();
            self.storage = HashMap::new();

            Ok(root)
        }
    }

    pub fn storage_root(&mut self, address: &H160) -> anyhow::Result<H256> {
        let storage = self.storage.remove(address).unwrap_or_default();
        let mut dirty_storage: Vec<(NibbleList, Option<SmallVec<[u8; 36]>>)> = Vec::new();
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

        let mut trie_prefix = vec![2];
        trie_prefix.extend_from_slice(&get_internal_key(address));
        let mut walker = Walker::new(&trie_prefix, dirty_storage, &mut self.tx);
        walker.root()
    }

    pub fn commit(mut self) -> anyhow::Result<()> {
        self.state_root()?;
        self.tx.commit()?;
        Ok(())
    }
    /*
    pub fn debug_dump_db(&mut self) -> anyhow::Result<()> {
        self.tx.debug_dump_db();
        Ok(())
    }
    */
}
