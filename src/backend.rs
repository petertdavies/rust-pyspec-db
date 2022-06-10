use std::borrow::Cow;
use std::ops::Bound::{Excluded, Unbounded};

use anyhow;
use arrayvec::ArrayVec;
use libmdbx::{
    Environment, EnvironmentFlags, Geometry, Mode, SyncMode, Transaction, WriteFlags, WriteMap, RW,
};
use smallvec::SmallVec;
use std::collections::BTreeMap;

pub struct Backend {
    cache: BTreeMap<ArrayVec<u8, 96>, Option<SmallVec<[u8; 128]>>>,
    disk: Option<Environment<WriteMap>>,
}

impl Backend {
    pub fn memory() -> anyhow::Result<Self> {
        Ok(Self {
            cache: BTreeMap::new(),
            disk: None,
        })
    }

    pub fn file(path: &std::path::Path) -> anyhow::Result<Self> {
        let mut builder = Environment::<WriteMap>::new();
        builder.set_flags(EnvironmentFlags {
            exclusive: true,
            ..EnvironmentFlags::default()
        });
        builder.set_geometry(Geometry {
            size: Some(0..(2_usize).pow(40)),
            growth_step: Some((2_isize).pow(20)),
            ..Geometry::default()
        });
        Ok(Self {
            cache: BTreeMap::new(),
            disk: Some(builder.open(path)?),
        })
    }

    pub fn begin_mut(&mut self) -> anyhow::Result<BackendTransaction> {
        Ok(match &self.disk {
            None => BackendTransaction {
                cache: &mut self.cache,
                txn: None,
            },
            Some(disk) => {
                let txn = disk.begin_rw_txn()?;
                BackendTransaction {
                    cache: &mut self.cache,
                    txn: Some(txn),
                }
            }
        })
    }
}

pub struct BackendTransaction<'txn> {
    cache: &'txn mut BTreeMap<ArrayVec<u8, 96>, Option<SmallVec<[u8; 128]>>>,
    txn: Option<Transaction<'txn, RW, WriteMap>>,
}

impl<'txn> BackendTransaction<'txn> {
    pub fn get(&'txn self, key: &[u8]) -> anyhow::Result<Option<Cow<'txn, [u8]>>> {
        Ok(if let Some(value) = self.cache.get(key) {
            value.as_ref().map(|value| Cow::from(value.as_slice()))
        } else {
            match &self.txn {
                None => None,
                Some(txn) => txn.get(&txn.open_db(None)?, key)?,
            }
        })
    }

    pub fn put(&mut self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.cache
            .insert(key.try_into()?, Some(SmallVec::from_slice(value)));
        Ok(())
    }

    pub fn delete(&mut self, key: &[u8]) -> anyhow::Result<()> {
        self.cache.insert(key.try_into()?, None);
        Ok(())
    }

    pub fn clear_prefix(&mut self, prefix: &[u8]) -> anyhow::Result<()> {
        let to_delete: Vec<_> = self
            .cache
            .range((Excluded(ArrayVec::<u8, 96>::try_from(prefix)?), Unbounded))
            .map(|x| x.0)
            .take_while(|x| x.starts_with(prefix))
            .cloned()
            .collect();
        for key in to_delete {
            self.cache.remove(&key);
        }
        if let Some(txn) = &self.txn {
            let mut cursor = txn.cursor(&txn.open_db(None)?)?;
            let ((), ()) = match cursor.set_range(prefix)? {
                Some(x) => x,
                None => return Ok(()),
            };
            loop {
                match cursor.next()? {
                    None => break,
                    Some(((), ())) => {}
                }
                match cursor.get_current::<Cow<[u8]>, ()>()? {
                    None => break,
                    Some((key, ())) => {
                        if !key.starts_with(prefix) {
                            break;
                        }
                    }
                };
                cursor.del(WriteFlags::default())?;
            }
        }
        Ok(())
    }

    pub fn commit(self) -> anyhow::Result<()> {
        match self.txn {
            None => Ok(()),
            Some(txn) => {
                let db = txn.open_db(None)?;
                let mut cursor = txn.cursor(&db)?;
                for (key, value) in self.cache.iter() {
                    if let Some(value) = value {
                        cursor.put(key, value, WriteFlags::default())?;
                    } else {
                        let x: Option<()> = cursor.set(key)?;
                        if x.is_some() {
                            txn.del(&db, key, None)?;
                        }
                    }
                }
                self.cache.clear();
                txn.commit()?;
                Ok(())
            }
        }
    }
}
