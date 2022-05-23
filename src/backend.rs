use std::ops::Bound::{Excluded, Unbounded};

use anyhow;
use arrayvec::ArrayVec;
use smallvec::SmallVec;
use std::collections::BTreeMap;

use crate::structs::InternalNode;

pub enum Backend {
    InMemory(BTreeMap<ArrayVec<u8, 96>, SmallVec<[u8; 128]>>),
}

impl Backend {
    pub fn open_in_memory() -> anyhow::Result<Self> {
        Ok(Self::InMemory(BTreeMap::new()))
    }

    pub fn begin_mutable(&mut self) -> anyhow::Result<BackendTransaction> {
        match self {
            Self::InMemory(btree) => Ok(BackendTransaction::InMemory(btree)),
        }
    }
}

pub enum BackendTransaction<'txn> {
    InMemory(&'txn mut BTreeMap<ArrayVec<u8, 96>, SmallVec<[u8; 128]>>),
}

impl<'txn> BackendTransaction<'txn> {
    pub fn get(&self, key: &[u8]) -> anyhow::Result<Option<&[u8]>> {
        match self {
            Self::InMemory(btree) => Ok(btree.get(key).map(|x| x.as_slice())),
        }
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::InMemory(btree) => {
                btree.insert(key.try_into()?, SmallVec::from_slice(value));
                Ok(())
            }
        }
    }

    pub fn delete(&mut self, key: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::InMemory(btree) => {
                btree.remove(key);
                Ok(())
            }
        }
    }

    pub fn clear_prefix(&mut self, prefix: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::InMemory(btree) => {
                let to_delete: Vec<_> = btree
                    .range((Excluded(ArrayVec::<u8, 96>::try_from(prefix)?), Unbounded))
                    .map(|x| x.0)
                    .take_while(|x| x.starts_with(prefix))
                    .cloned()
                    .collect();
                for key in to_delete {
                    btree.remove(&key);
                }
                Ok(())
            }
        }
    }

    pub fn debug_dump_db(&self) {
        match self {
            Self::InMemory(btree) => {
                println!("==START DEBUG DUMP==");
                for (key, value) in btree.iter() {
                    if key[0] == 2 {
                        println!("{:?}: {:?}", key, InternalNode::unmarshal(value))
                    } else {
                        println!("{:?}: {:?}", key, value)
                    }
                }
                println!("==END DEBUG DUMP==");
            }
        }
    }

    pub fn commit(self) -> anyhow::Result<()> {
        anyhow::bail!("Cannot commit a memory DB")
    }
}
