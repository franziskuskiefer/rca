extern crate rust_crypto;
use rust_crypto::cipher::*;
use rust_crypto::registry::*;

use rand::Rng;

mod dummy_provider;

fn enc_dec_sym_test(cipher: &Box<SymmetricCipherOps>) {
    let key = rand::thread_rng().gen::<[u8; 32]>();
    let iv = rand::thread_rng().gen::<[u8; 32]>();
    let aad = rand::thread_rng().gen::<[u8; 32]>();
    let m = rand::thread_rng().gen::<[u8; 32]>();

    let c = cipher.encrypt(&key, &iv, &aad, &m);
    let m_dec = match cipher.decrypt(&key, &iv, &aad, &c) {
        Err(e) => {
            println!("Error decrypting {:?}", e);
            vec![]
        }
        Ok(v) => v,
    };
    assert_eq!(m[..], m_dec[..]);
}

fn enc_dec_asym_test(cipher: &Box<AsymmetricCipherOps>) {
    let key_pair = cipher.gen_keypair();
    let nonce = cipher.gen_nonce();
    let m = rand::thread_rng().gen::<[u8; 32]>();

    let c = cipher.encrypt(&key_pair.public_bytes, &nonce, &m);
    let m_dec = match cipher.decrypt(&key_pair, &nonce, &c) {
        Err(e) => {
            println!("Error decrypting {:?}", e);
            vec![]
        }
        Ok(v) => v,
    };
    assert_eq!(m[..], m_dec[..]);
}

#[test]
fn test_unsupported_algorithm() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::DummyProvider::new());

    assert_eq!(registry.supports("unimplemented cipher"), false);
    let cipher_result = registry.get_symmetric_cipher("unimplemented cipher");
    assert_eq!(cipher_result.is_err(), true);
}

#[test]
fn test_sym_cipher() {
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
    enc_dec_sym_test(cipher);
}

#[test]
fn test_asym_cipher() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::DummyProvider::new());
    assert_eq!(registry.supports("noop asym"), true);

    // Get cipher through registry.
    let cipher_result = registry.get_asymmetric_cipher("noop asym");
    assert_eq!(cipher_result.is_ok(), true);
    let cipher = match cipher_result.ok() {
        Some(v) => v,
        None => return,
    };
    enc_dec_asym_test(cipher);
}
