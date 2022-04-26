pub mod check_trie;
pub mod get_prefix;

use ethereum_pyspec_db::util::keccak256;
use ethereum_pyspec_db::*;
use ethereum_types::{Address, H256, U256};
use once_cell::sync::Lazy;
use rand::{seq::IteratorRandom, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rlp;
use std::collections::HashMap;
use std::str::FromStr;
use tempfile;

use crate::get_prefix::{get_address_from_index, get_address_with_prefix_nibbles};

static ACCOUNT1: Account = Account {
    nonce: 1,
    balance: U256::zero(),
    code: vec![],
};

static ACCOUNT2: Account = Account {
    nonce: 2,
    balance: U256::zero(),
    code: vec![],
};

static TESTS: &[&[(&[u8], Option<&Account>)]] = &[
    &[],
    &[(&[0, 0, 1, 1, 1, 1], Some(&ACCOUNT1))],
    &[(&[0, 0, 1, 1, 1, 1], Some(&ACCOUNT2))],
    &[(&[0, 0, 1, 1, 1, 1], None)],
    &[
        (&[1, 0, 1, 1, 0, 0], Some(&ACCOUNT1)),
        (&[1, 0, 1, 1, 0, 1], Some(&ACCOUNT1)),
    ],
    &[(&[1, 0, 2, 0, 0, 0], Some(&ACCOUNT1))],
    &[(&[1, 0, 1, 1, 1, 1], None)],
    &[
        (&[1, 0, 1, 1, 1, 2], Some(&ACCOUNT1)),
        (&[1, 0, 1, 1, 1, 3], Some(&ACCOUNT1)),
    ],
    &[
        (&[1, 0, 1, 1, 0, 0], None),
        (&[1, 0, 1, 1, 0, 1], None),
        (&[1, 0, 1, 1, 1, 2], None),
        (&[1, 0, 1, 1, 1, 3], None),
    ],
    &[
        (&[2, 0, 0, 0, 0, 0], Some(&ACCOUNT1)),
        (&[2, 0, 0, 0, 1, 0], Some(&ACCOUNT1)),
    ],
    &[(&[2, 0, 0, 0, 1, 0], Some(&ACCOUNT2))],
    &[
        (&[3, 0, 0, 0, 0, 0], Some(&ACCOUNT1)),
        (&[3, 0, 0, 0, 0, 1], Some(&ACCOUNT1)),
        (&[3, 0, 0, 1, 0, 0], Some(&ACCOUNT1)),
    ],
    &[(&[3, 0, 0, 1, 0, 0], None)],
];

fn with_temp_db<T>(f: impl for<'env, 'a> FnOnce(&'a mut MutableTransaction<'env>) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let db = DB::create(dir.path(), false).unwrap();
    let mut txn = db.begin_mutable().unwrap();
    let res = f(&mut txn);
    dir.close().unwrap();
    res
}

fn do_tests<'env>(txn: &mut MutableTransaction<'env>) {
    let mut trie_contents = HashMap::<Address, Account>::new();
    for test in TESTS {
        for (prefix_nibbles, account) in *test {
            let address = get_address_with_prefix_nibbles(prefix_nibbles);
            txn.set_account(address, account.cloned());
            if let Some(account) = account {
                trie_contents.insert(address, (*account).clone());
            } else {
                trie_contents.remove(&address);
            }
        }
        assert_eq!(
            txn.state_root().unwrap(),
            check_trie::calc_root(&trie_contents)
        );
    }
}

#[test]
fn test() {
    with_temp_db(do_tests)
}

#[test]
fn random_test() {
    with_temp_db(do_random_tests);
}

const NUM_RANDOM_TESTS: usize = 1000;

fn do_random_tests<'env>(txn: &mut MutableTransaction<'env>) {
    // Use a deterministic RNG
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut trie_contents = HashMap::<Address, Account>::new();
    for _ in 0..NUM_RANDOM_TESTS {
        loop {
            let (address, account) = gen_op(&trie_contents, &mut rng);
            txn.set_account(address, account.clone());
            if let Some(account) = account {
                trie_contents.insert(address, account);
            } else {
                trie_contents.remove(&address);
            }
            if rng.gen_bool(0.75) {
                break;
            }
        }
        assert_eq!(
            txn.state_root().unwrap(),
            check_trie::calc_root(&trie_contents)
        );
    }
}

fn gen_op(
    trie_contents: &HashMap<Address, Account>,
    rng: &mut impl Rng,
) -> (Address, Option<Account>) {
    if trie_contents.len() == 0 || rng.gen_bool(0.4) {
        let index = rng.gen_range(0..=get_prefix::MAX_INDEX);
        let account = Some(if rng.gen_bool(0.5) {
            ACCOUNT1.clone()
        } else {
            ACCOUNT2.clone()
        });
        (get_address_from_index(index), account)
    } else {
        let address = trie_contents.keys().choose(rng).unwrap();
        if rng.gen_bool(0.5) {
            (*address, None)
        } else {
            if trie_contents[address] == ACCOUNT1 {
                (*address, Some(ACCOUNT2.clone()))
            } else {
                (*address, Some(ACCOUNT1.clone()))
            }
        }
    }
}
