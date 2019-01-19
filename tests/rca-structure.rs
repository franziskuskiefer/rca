#![allow(unused)]

extern crate rust_crypto;
use rust_crypto::cipher::*;
use rust_crypto::digest::*;
use rust_crypto::registry::*;

use rand::Rng;

mod dummy_provider;

fn enc_dec_sym_test(cipher: &Box<SymmetricCipher>) {
    let key = cipher.gen_key();
    let iv = cipher.gen_iv();
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

fn enc_dec_asym_test(cipher: &Box<AsymmetricCipher>) {
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

// TODO: write useful test.
fn md_test(md: &Box<MessageDigest>, md2: &mut Box<MessageDigest>, md3: &mut Box<MessageDigest>) {
    let m: Vec<u8> = (0..77).map(|_| rand::random::<u8>()).collect();

    let hash = md.hash(&m);
    let hash2 = md.hash(&m);
    assert_eq!(hash[..], hash2[..]);

    md2.update(&m);
    md2.update(&m);
    let h = md2.finish(None);

    md3.update(&m);
    md3.update(&m);
    let h2 = md3.finish(Some(&m));
    assert_ne!(h[..], h2[..]);
}

#[test]
fn test_unsupported_algorithm() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::DummyProvider::new());
    registry.add(dummy_provider::TestBaseProvider::new());

    assert_eq!(registry.supports("unimplemented cipher"), false);
    let cipher_result = registry.get_symmetric_cipher("unimplemented cipher");
    assert_eq!(cipher_result.is_err(), true);
}

#[test]
fn test_sym_cipher_dummy() {
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
    enc_dec_sym_test(&cipher);
}

#[test]
fn test_asym_cipher_dummy() {
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
    enc_dec_asym_test(&cipher);
}

#[test]
fn test_sym_cipher_base() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::TestBaseProvider::new());
    assert_eq!(registry.supports("noop"), true);

    // Get cipher through registry.
    let cipher_result = registry.get_symmetric_cipher("noop");
    assert_eq!(cipher_result.is_ok(), true);
    let cipher = match cipher_result.ok() {
        Some(v) => v,
        None => {
            assert!(false);
            return;
        }
    };
    enc_dec_sym_test(&cipher);
}

#[test]
fn test_asym_cipher_base() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::TestBaseProvider::new());
    assert_eq!(registry.supports("noop asym"), true);

    // Get cipher through registry.
    let cipher_result = registry.get_asymmetric_cipher("noop asym");
    assert_eq!(cipher_result.is_ok(), true);
    let cipher = match cipher_result.ok() {
        Some(v) => v,
        None => return,
    };
    enc_dec_asym_test(&cipher);
}

#[test]
fn test_message_digest_base() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(dummy_provider::TestBaseProvider::new());
    assert_eq!(registry.supports("stupid digest"), true);

    // Get cipher through registry.
    let md_result = registry.get_messagedigest("stupid digest");
    assert_eq!(md_result.is_ok(), true);
    let md = match md_result.ok() {
        Some(v) => v,
        None => return,
    };
    let mut md2 = registry.get_messagedigest("stupid digest").unwrap();
    let mut md3 = registry.get_messagedigest("stupid digest").unwrap();
    md_test(&md, &mut md2, &mut md3);
}
