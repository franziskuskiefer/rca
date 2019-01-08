extern crate rust_crypto;
use rust_crypto::cipher::*;
use rust_crypto::registry::*;

use rand::Rng;

mod dummy_provider;

fn enc_dec_test(cipher: &Box<SymmetricCipherOps>) {
    let key = rand::thread_rng().gen::<[u8; 32]>();
    let iv = rand::thread_rng().gen::<[u8; 32]>();
    let aad = rand::thread_rng().gen::<[u8; 32]>();
    let m = rand::thread_rng().gen::<[u8; 32]>();

    let c = cipher.encrypt(&key, &iv, &aad, &m);
    let m_dec = match cipher.decrypt(&key, &iv, &aad, c.get_c()) {
        Err(e) => {
            println!("Error decrypting {:?}", e);
            vec![]
        }
        Ok(v) => {
            v
        }
    };
    assert_eq!(m[..], m_dec[..]);
}

#[test]
fn test_provider() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::DummyProvider::new());
    assert_eq!(registry.supports("noop"), true);

    // Get cipher through registry.
    let cipher_result = registry.get_symmetric_cipher("noop");
    assert_eq!(cipher_result.is_ok(), true);
    let cipher = match cipher_result.ok() {
        Some(v) => v,
        None => return,
    };
    enc_dec_test(cipher);
}

