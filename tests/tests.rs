pub mod check_trie;
pub mod get_prefix;

use ethereum_pyspec_db::*;
use ethereum_types::{Address, U256};
use once_cell::sync::Lazy;
use rand::{seq::IteratorRandom, Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::HashMap;
use tempfile;

use crate::get_prefix::{get_address_from_index, get_address_with_prefix_nibbles};

static LAZY_NONE: Lazy<Option<Account>> = Lazy::new(|| None);

static ACCOUNT1: Lazy<Option<Account>> = Lazy::new(|| {
    Some(Account {
        nonce: 1,
        balance: U256::zero(),
        code_hash: *EMPTY_CODE_HASH,
    })
});

static ACCOUNT2: Lazy<Option<Account>> = Lazy::new(|| {
    Some(Account {
        nonce: 2,
        balance: U256::zero(),
        code_hash: *EMPTY_CODE_HASH,
    })
});

static TESTS: &[&[(&[u8], &Lazy<Option<Account>>)]] = &[
    &[],
    &[(&[0, 0, 1, 1, 1, 1], &ACCOUNT1)],
    &[(&[0, 0, 1, 1, 1, 1], &ACCOUNT2)],
    &[(&[0, 0, 1, 1, 1, 1], &LAZY_NONE)],
    &[
        (&[1, 0, 1, 1, 0, 0], &ACCOUNT1),
        (&[1, 0, 1, 1, 0, 1], &ACCOUNT1),
    ],
    &[(&[1, 0, 2, 0, 0, 0], &ACCOUNT1)],
    &[(&[1, 0, 1, 1, 1, 1], &LAZY_NONE)],
    &[
        (&[1, 0, 1, 1, 1, 2], &ACCOUNT1),
        (&[1, 0, 1, 1, 1, 3], &ACCOUNT1),
    ],
    &[
        (&[1, 0, 1, 1, 0, 0], &LAZY_NONE),
        (&[1, 0, 1, 1, 0, 1], &LAZY_NONE),
        (&[1, 0, 1, 1, 1, 2], &LAZY_NONE),
        (&[1, 0, 1, 1, 1, 3], &LAZY_NONE),
    ],
    &[
        (&[2, 0, 0, 0, 0, 0], &ACCOUNT1),
        (&[2, 0, 0, 0, 1, 0], &ACCOUNT1),
    ],
    &[(&[2, 0, 0, 0, 1, 0], &ACCOUNT2)],
    &[
        (&[3, 0, 0, 0, 0, 0], &ACCOUNT1),
        (&[3, 0, 0, 0, 0, 1], &ACCOUNT1),
        (&[3, 0, 0, 1, 0, 0], &ACCOUNT1),
    ],
    &[(&[3, 0, 0, 1, 0, 0], &LAZY_NONE)],
];

fn with_memory<T>(f: impl for<'a> FnOnce(&'a mut DB) -> T) -> T {
    let mut db = DB::open_in_memory().unwrap();
    let res = f(&mut db);
    res
}

fn with_temp_db<T>(f: impl for<'a> FnOnce(&'a mut DB) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let mut db = DB::open_in_memory().unwrap();
    let res = f(&mut db);
    dir.close().unwrap();
    res
}

fn do_tests<'env>(db: &mut DB) {
    let mut trie_contents = HashMap::<Address, Account>::new();
    for test in TESTS {
        let mut txn = db.begin_mutable().unwrap();
        for (prefix_nibbles, account) in *test {
            let address = get_address_with_prefix_nibbles(prefix_nibbles);
            txn.set_account(address, (**account).clone());
            if let Some(account) = &***account {
                trie_contents.insert(address, account.clone());
            } else {
                trie_contents.remove(&address);
            }
        }
        let state_root = txn.state_root().unwrap();
        assert_eq!(state_root, check_trie::calc_root(&trie_contents));
        txn.commit().unwrap();
    }
}

#[test]
fn nonrandom_test() {
    with_memory(do_tests)
}

#[test]
fn random_test() {
    with_memory(do_random_tests);
}

#[test]
fn nonrandom_with_temp_db() {
    with_temp_db(do_tests)
}

const NUM_RANDOM_TESTS: usize = 1000;

fn do_random_tests(db: &mut DB) {
    // Use a deterministic RNG
    let mut rng = ChaCha8Rng::seed_from_u64(0);
    let mut trie_contents = HashMap::<Address, Account>::new();
    for _ in 0..NUM_RANDOM_TESTS {
        let mut txn = db.begin_mutable().unwrap();
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
        txn.commit().unwrap();
    }
}

fn gen_op(
    trie_contents: &HashMap<Address, Account>,
    rng: &mut impl Rng,
) -> (Address, Option<Account>) {
    // Slight bias towards deleting to avoid tries with only branch nodes
    if trie_contents.len() == 0 || rng.gen_bool(0.4) {
        let index = rng.gen_range(0..=get_prefix::MAX_INDEX);
        let account = if rng.gen_bool(0.5) {
            &*ACCOUNT1
        } else {
            &*ACCOUNT2
        };
        (get_address_from_index(index), account.clone())
    } else {
        let address = trie_contents.keys().choose(rng).unwrap();
        if rng.gen_bool(0.5) {
            (*address, None)
        } else {
            if Some(trie_contents[address].clone()) == *ACCOUNT1 {
                (*address, ACCOUNT2.clone())
            } else {
                (*address, ACCOUNT1.clone())
            }
        }
    }
}
