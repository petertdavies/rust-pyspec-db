use ethereum_types::H256;
use once_cell::sync::Lazy;
use sha3::{Digest, Keccak256};

pub static EMPTY_CODE_HASH: Lazy<H256> = Lazy::new(|| keccak256(&[]));

pub fn keccak256(data: impl AsRef<[u8]>) -> H256 {
    H256::from_slice(&Keccak256::digest(data.as_ref()))
}

pub fn common_prefix(xs: &[u8], ys: &[u8]) -> usize {
    xs.iter().zip(ys).take_while(|(x, y)| x == y).count()
}
