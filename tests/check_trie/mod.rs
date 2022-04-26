use ethereum_types::{Address, H256};
use rlp::RlpStream;
use std::collections::HashMap;
use trie;

use ethereum_pyspec_db::util::keccak256;
use ethereum_pyspec_db::walk::EMPTY_TRIE_ROOT;
use ethereum_pyspec_db::Account;

fn encode_account_no_storage(account: &Account) -> Vec<u8> {
    let mut s = RlpStream::new_list(4);
    s.append(&account.nonce)
        .append(&account.balance)
        .append(&*EMPTY_TRIE_ROOT)
        .append(&keccak256(&account.code));
    s.out().to_vec()
}

pub fn calc_root(contents: &HashMap<Address, Account>) -> H256 {
    let trie_items: HashMap<Vec<u8>, Vec<u8>> = contents
        .iter()
        .map(|(address, account)| {
            (
                keccak256(address).as_bytes().to_vec(),
                encode_account_no_storage(account),
            )
        })
        .collect();
    H256::from_slice(&trie::build(&trie_items).0)
}
