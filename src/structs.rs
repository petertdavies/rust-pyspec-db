use arrayvec::ArrayVec;
use ethereum_types::{H256, U256};
use rlp::RlpStream;
use smallvec::SmallVec;

use crate::util::{keccak256, EMPTY_CODE_HASH};

pub type Db_Value = SmallVec<[u8; 64]>;
pub type NibbleList = ArrayVec<u8, 64>;

pub fn marshal_nibble_list(nibbles: &[u8]) -> ArrayVec<u8, 33> {
    let mut res = ArrayVec::new();
    res.push(nibbles.len() as u8);
    for i in 0..nibbles.len() / 2 {
        res.push((nibbles[i * 2] << 4) + nibbles[i * 2 + 1]);
    }
    if nibbles.len() % 2 == 1 {
        res.push(nibbles.last().unwrap() << 4);
    }
    res
}

pub fn unmarshal_nibble_list(data: &[u8]) -> (NibbleList, usize) {
    let nibbles_len = data[0] as usize;
    let mut nibble_list = NibbleList::new();
    for i in 1..nibbles_len / 2 + 1 {
        nibble_list.push(data[i] >> 4);
        nibble_list.push(data[i] & 0x0F);
    }
    if nibbles_len % 2 == 1 {
        nibble_list.push(data[nibbles_len / 2 + 1] >> 4);
    }
    (nibble_list, (data[0] as usize + 1) / 2 + 1)
}

pub fn nibble_list_to_key(nibbles: &[u8]) -> ArrayVec<u8, 64> {
    let mut res = ArrayVec::new();
    let mut terminal_zeros = nibbles.iter().rev().take_while(|x| **x == 0).count();
    for i in 0..nibbles.len() / 2 {
        res.push((nibbles[i * 2] << 4) + nibbles[i * 2 + 1]);
    }
    if nibbles.len() % 2 == 1 {
        res.push(nibbles.last().unwrap() << 4);
        if *nibbles.last().unwrap() == 0 {
            terminal_zeros -= 1;
        }
    }
    // Should be `.div_ceil()`
    for _ in 0..(terminal_zeros + 1) / 2 {
        res.push(0);
    }
    res
}

pub fn hp_encode_nibble_list(nibble_list: &[u8], is_leaf: bool) -> ArrayVec<u8, 33> {
    let mut res = ArrayVec::new();
    if nibble_list.len() % 2 == 0 {
        res.push((2 * is_leaf as u8) << 4);
        for i in 0..nibble_list.len() / 2 {
            res.push((nibble_list[i * 2] << 4) + nibble_list[i * 2 + 1]);
        }
    } else {
        res.push(((2 * (is_leaf as u8) + 1) << 4) + nibble_list[0]);
        for i in 0..nibble_list.len() / 2 {
            res.push((nibble_list[i * 2 + 1] << 4) + nibble_list[i * 2 + 2]);
        }
    }
    res
}

pub fn get_internal_key(bytes: impl AsRef<[u8]>) -> NibbleList {
    let hash = keccak256(bytes);
    let mut res = NibbleList::new();
    for byte in hash.as_bytes() {
        res.push(byte >> 4);
        res.push(byte & 0x0F);
    }
    res
}

fn hash_if_long(data: &[u8]) -> ArrayVec<u8, 32> {
    if data.len() < 32 {
        ArrayVec::try_from(data.as_ref()).unwrap()
    } else {
        keccak256(data).as_ref().try_into().unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InternalNode {
    Leaf {
        rest_of_key: NibbleList,
        value: SmallVec<[u8; 36]>,
    },
    Branch {
        extension_nibbles: NibbleList,
        subnodes: [ArrayVec<u8, 32>; 16],
    },
}

impl InternalNode {
    pub fn marshal(&self) -> Db_Value {
        let mut res = Db_Value::new();
        match self {
            Self::Leaf { rest_of_key, value } => {
                res.push(0);
                res.extend_from_slice(&marshal_nibble_list(rest_of_key));
                res.extend_from_slice(value);
            }
            Self::Branch {
                extension_nibbles,
                subnodes,
            } => {
                res.push(1);
                res.extend_from_slice(&marshal_nibble_list(extension_nibbles));
                let mut subnodes_mask: u16 = 0;
                for (i, subnode) in subnodes.iter().enumerate() {
                    if !subnode.is_empty() {
                        subnodes_mask |= 1 << i
                    }
                }
                res.extend_from_slice(&subnodes_mask.to_be_bytes());
                for subnode in subnodes {
                    if !subnode.is_empty() {
                        res.push(subnode.len() as u8);
                        res.extend_from_slice(subnode);
                    }
                }
            }
        }
        res
    }

    pub fn unmarshal(data: &[u8]) -> Self {
        if data[0] == 0 {
            let (rest_of_key, bytes_consumed) = unmarshal_nibble_list(&data[1..]);
            Self::Leaf {
                rest_of_key,
                value: SmallVec::from_slice(&data[1 + bytes_consumed..]),
            }
        } else {
            let (extension_nibbles, mut bytes_consumed) = unmarshal_nibble_list(&data[1..]);
            bytes_consumed += 1;
            let mut subnodes: [ArrayVec<u8, 32>; 16] = Default::default();
            let subnode_mask =
                u16::from_be_bytes(data[bytes_consumed..bytes_consumed + 2].try_into().unwrap());
            bytes_consumed += 2;
            for i in 0..16 {
                if subnode_mask & (1 << i) != 0 {
                    let len = data[bytes_consumed] as usize;
                    bytes_consumed += 1;
                    subnodes[i] =
                        ArrayVec::try_from(&data[bytes_consumed..bytes_consumed + len]).unwrap();
                    bytes_consumed += len;
                }
            }
            Self::Branch {
                extension_nibbles,
                subnodes,
            }
        }
    }

    pub fn encode(&self) -> ArrayVec<u8, 32> {
        match self {
            Self::Leaf { rest_of_key, value } => {
                let mut s = RlpStream::new_list(2);
                s.append(&hp_encode_nibble_list(&rest_of_key, true).as_slice())
                    .append(&value.as_slice());
                hash_if_long(&s.out())
            }
            Self::Branch {
                extension_nibbles,
                subnodes,
            } => {
                let mut s = RlpStream::new_list(17);
                for subnode in subnodes {
                    if subnode.is_empty() {
                        s.append_empty_data()
                    } else {
                        s.append(&subnode.as_slice())
                    };
                }
                s.append_empty_data();
                let branch_node = hash_if_long(&s.out());
                if extension_nibbles.len() != 0 {
                    let mut s = RlpStream::new_list(2);
                    s.append(&hp_encode_nibble_list(extension_nibbles, false).as_slice())
                        .append(&branch_node.as_slice());
                    hash_if_long(&s.out())
                } else {
                    branch_node
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
}

impl Account {
    pub fn marshal(&self) -> Db_Value {
        debug_assert_ne!(self.code_hash, H256::zero());
        let mut res = Db_Value::new();
        let nonce_len = 8 - (self.nonce.leading_zeros() / 8) as usize;
        res.push(nonce_len as u8);
        res.extend_from_slice(&self.nonce.to_be_bytes()[8 - nonce_len..]);
        let balance_len = 32 - (self.balance.leading_zeros() / 8) as usize;
        let mut balance_be = [0; 32];
        self.balance.to_big_endian(&mut balance_be);
        res.push(balance_len as u8);
        res.extend_from_slice(&balance_be[32 - balance_len..]);
        if self.code_hash != *EMPTY_CODE_HASH {
            res.extend_from_slice(self.code_hash.as_bytes());
        };
        res
    }

    pub fn unmarshal(data: &[u8]) -> Self {
        let mut nonce_data = [0; 8];
        let nonce_len = data[0] as usize;
        nonce_data[8 - nonce_len..].copy_from_slice(&data[1..1 + nonce_len]);
        let mut bytes_consumed = 1 + nonce_len;
        let balance_len = data[bytes_consumed] as usize;
        let mut balance_data = [0; 32];
        balance_data[32 - balance_len..]
            .copy_from_slice(&data[bytes_consumed + 1..bytes_consumed + 1 + balance_len]);
        bytes_consumed += 1 + balance_len;
        let code_hash = if data.len() == bytes_consumed {
            *EMPTY_CODE_HASH
        } else {
            H256::from_slice(&data[bytes_consumed..bytes_consumed + 32])
        };
        Self {
            nonce: u64::from_be_bytes(nonce_data),
            balance: U256::from_big_endian(&balance_data),
            code_hash,
        }
    }
}

pub fn marshal_storage(value: U256) -> Db_Value {
    let mut buf = [0; 32];
    value.to_big_endian(&mut buf);
    Db_Value::from_slice(&buf[(value.leading_zeros() / 8) as usize..])
}

pub fn unmarshal_storage(data: &[u8]) -> U256 {
    let mut buf = [0; 32];
    buf[32 - data.len()..].copy_from_slice(data);
    U256::from_big_endian(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    static NIBBLE_LIST_TESTS: &[&[u8]] = &[&[], &[1, 2, 3], &[1, 2, 3, 4]];

    #[test]
    fn test_nibble_list() {
        for test in NIBBLE_LIST_TESTS {
            let nibble_list = ArrayVec::try_from(*test).unwrap();
            assert_eq!(
                unmarshal_nibble_list(&marshal_nibble_list(&nibble_list)).0,
                nibble_list
            )
        }
    }

    static HP_ENCODE_TESTS: &[(&[u8], bool, &[u8])] = &[
        (&[1, 2, 3], true, &[49, 35]),
        (&[1, 2, 3], false, &[17, 35]),
        (&[1, 2, 3, 4], true, &[32, 18, 52]),
        (&[1, 2, 3, 4], false, &[0, 18, 52]),
    ];

    #[test]
    fn test_hp_encode() {
        for test in HP_ENCODE_TESTS {
            assert_eq!(&hp_encode_nibble_list(test.0, test.1), test.2);
        }
    }

    #[test]
    fn test_internal_node() {
        let mut subnodes: [ArrayVec<u8, 32>; 16] = Default::default();
        subnodes[0] = [1, 1, 1].as_slice().try_into().unwrap();
        let internal_node = InternalNode::Branch {
            extension_nibbles: [1, 2, 3].as_slice().try_into().unwrap(),
            subnodes,
        };
        assert_eq!(
            internal_node,
            InternalNode::unmarshal(&internal_node.marshal())
        );
    }

    #[test]
    fn test_marshal_storage() {
        let value = U256::from(15897243 as u64);
        assert_eq!(value, unmarshal_storage(&marshal_storage(value)));
    }
}
