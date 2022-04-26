use ethereum_types::H256;
use lmdb::{Cursor, RwCursor, WriteFlags};
use lmdb_sys::MDB_SET_KEY;
use sha3::{Digest, Keccak256};

pub fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(&Keccak256::digest(data.as_ref()))
}

pub fn common_prefix(xs: &[u8], ys: &[u8]) -> usize {
    xs.iter().zip(ys).take_while(|(x, y)| x == y).count()
}

pub fn cursor_get<'txn>(
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

pub fn cursor_delete<'txn>(
    cursor: &mut RwCursor<'txn>,
    key: impl AsRef<[u8]>,
) -> Result<(), lmdb::Error> {
    let res = cursor.get(Some(key.as_ref()), None, MDB_SET_KEY);
    match res {
        Ok((_, _)) => cursor.del(WriteFlags::empty()),
        Err(lmdb::Error::NotFound) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn encode_nibble_list(nibble_list: &[u8], is_leaf: bool) -> Vec<u8> {
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

pub fn decode_nibble_list(bytes: &[u8]) -> (Vec<u8>, bool) {
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

pub fn get_internal_key(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    let hash = keccak256(bytes);
    let mut res = Vec::new();
    for byte in hash.as_bytes() {
        res.push(byte >> 4);
        res.push(byte & 0x0F);
    }
    res
}
