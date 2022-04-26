mod table;

use ethereum_types::H160;

const PREFIX_LEN: usize = 3;
const NUM_VALS: u8 = 4;

pub const MAX_INDEX: usize = (NUM_VALS as usize).pow(PREFIX_LEN as u32) - 1;

fn to_nibble_list(bytes: &[u8]) -> Vec<u8> {
    let mut res = Vec::with_capacity(bytes.len() * 2);
    for byte in bytes {
        res.push(byte >> 4);
        res.push(byte & 0x0F);
    }
    res
}

pub fn prefix_to_index(prefix: &[u8]) -> usize {
    assert_eq!(prefix.len(), PREFIX_LEN);
    let prefix_nibbles = to_nibble_list(prefix);
    let mut res: usize = 0;
    let mut acc: usize = 1;
    for val in prefix_nibbles {
        assert!(val < NUM_VALS);
        res += acc * (val as usize);
        acc *= NUM_VALS as usize;
    }
    res
}

pub fn nibbles_to_index(prefix_nibbles: &[u8]) -> usize {
    assert_eq!(prefix_nibbles.len(), PREFIX_LEN * 2);
    let mut res: usize = 0;
    let mut acc: usize = 1;
    for val in prefix_nibbles {
        assert!(val < &NUM_VALS);
        res += acc * (*val as usize);
        acc *= NUM_VALS as usize;
    }
    res
}

pub fn get_address_with_prefix(prefix: &[u8]) -> H160 {
    assert_eq!(prefix.len(), PREFIX_LEN);
    table::TABLE[prefix_to_index(prefix)]
}

pub fn get_address_with_prefix_nibbles(prefix: &[u8]) -> H160 {
    assert_eq!(prefix.len(), PREFIX_LEN * 2);
    table::TABLE[nibbles_to_index(prefix)]
}

pub fn get_address_from_index(index: usize) -> H160 {
    table::TABLE[index]
}
