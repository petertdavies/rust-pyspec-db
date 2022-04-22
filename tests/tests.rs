use ethereum_pyspec_db::*;
use ethereum_types::{H160, H256, U256};
use once_cell::sync::Lazy;
use std::str::FromStr;
use tempfile;

static ADDRESS1: Lazy<H160> =
    Lazy::new(|| H160::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap());
static ADDRESS2: Lazy<H160> =
    Lazy::new(|| H160::from_str("0x4ddc2d193948926d02f9b1fe9e1daa0718270ed5").unwrap());
static ADDRESS3: Lazy<H160> =
    Lazy::new(|| H160::from_str("0xa4dd6831114ec700000000000000000000000000").unwrap());
static ADDRESS4: Lazy<H160> =
    Lazy::new(|| H160::from_str("0xe417fbeebc1e9700000000000000000000000000").unwrap());
static ADDRESS5: Lazy<H160> =
    Lazy::new(|| H160::from_str("0x5c16fd151ae56edc8c5e01c49b45c8c207a82511").unwrap());

static EMPTY_ACCOUNT: Account = Account {
    nonce: 0,
    balance: U256::zero(),
    code: vec![],
};

static ANSWER1: Lazy<H256> = Lazy::new(|| {
    H256::from_str("0x4cf55af8e7cfddcc5be0795045819faf282068e6ba942b533274ace4bed32e85").unwrap()
});
static ANSWER2: Lazy<H256> = Lazy::new(|| {
    H256::from_str("0x2cb15015542c039ae73a869953c73f9eb06724676282bea1984496e44dbe601f").unwrap()
});
static ANSWER3: Lazy<H256> = Lazy::new(|| {
    H256::from_str("0x8b393a6f0892d429f7ccbba51ed5eebee861df8567647b974532346574ce6029").unwrap()
});
static ANSWER4: Lazy<H256> = Lazy::new(|| {
    H256::from_str("0x258a030250335c068fe1f04162ae22c2c42132178926d47871231707d7538b9a").unwrap()
});
static ANSWER5: Lazy<H256> = Lazy::new(|| {
    H256::from_str("0x28bba5b45246aa3d6cce32f5fcdf718c63fed4225d795f84ecb0e00a0df4e205").unwrap()
});

fn with_temp_db<T>(f: impl for<'env, 'a> FnOnce(&'a mut MutableTransaction<'env>) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let db = DB::create(dir.path(), false).unwrap();
    let mut txn = db.begin_mutable().unwrap();
    let res = f(&mut txn);
    dir.close().unwrap();
    res
}

fn do_test<'env>(txn: &mut MutableTransaction<'env>) {
    assert_eq!(txn.state_root().unwrap(), *EMPTY_TRIE_ROOT);
    txn.set_account(*ADDRESS1, Some(EMPTY_ACCOUNT.clone()));
    assert_eq!(txn.state_root().unwrap(), *ANSWER1);
    txn.set_account(*ADDRESS2, Some(EMPTY_ACCOUNT.clone()));
    assert_eq!(txn.state_root().unwrap(), *ANSWER2);
    txn.set_account(*ADDRESS3, Some(EMPTY_ACCOUNT.clone()));
    assert_eq!(txn.state_root().unwrap(), *ANSWER3);
    txn.set_account(*ADDRESS4, Some(EMPTY_ACCOUNT.clone()));
    assert_eq!(txn.state_root().unwrap(), *ANSWER4);
    txn.set_account(*ADDRESS5, Some(EMPTY_ACCOUNT.clone()));
    assert_eq!(txn.state_root().unwrap(), *ANSWER5);
    txn.set_account(*ADDRESS5, None);
    assert_eq!(txn.state_root().unwrap(), *ANSWER4);
    txn.set_account(*ADDRESS4, None);
    assert_eq!(txn.state_root().unwrap(), *ANSWER3);
    txn.set_account(*ADDRESS3, None);
    assert_eq!(txn.state_root().unwrap(), *ANSWER2);
    txn.set_account(*ADDRESS2, None);
    assert_eq!(txn.state_root().unwrap(), *ANSWER1);
    txn.set_account(*ADDRESS1, None);
    assert_eq!(txn.state_root().unwrap(), *EMPTY_TRIE_ROOT);
}

#[test]
fn test() {
    with_temp_db(do_test)
}
