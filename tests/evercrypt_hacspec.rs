#![allow(unused)]

use rca::aead::*;
use rca::digest::*;
use rca::registry::*;

use rand::Rng;

use rca::provider::evercrypt_provider::EvercryptProvider;
use rca::provider::hacspec_provider::HacspecProvider;

fn aead_enc_dec(cipher: &Box<dyn Aead>) {
    let key = cipher.key_gen();
    let nonce = cipher.nonce_gen();
    let aad = rand::thread_rng().gen::<[u8; 10]>();
    let m = rand::thread_rng().gen::<[u8; 32]>();

    let (c, tag) = cipher.encrypt(&key, &nonce, &aad, &m).unwrap();
    let m_dec = match cipher.decrypt(&key, &nonce, &aad, &c, &tag) {
        Err(e) => {
            println!("Error decrypting {:?}", e);
            vec![]
        }
        Ok(v) => v,
    };
    assert_eq!(m[..], m_dec[..]);
}

fn md_test(md: &Box<dyn Digest>, md2: &mut Box<dyn Digest>, md3: &mut Box<dyn Digest>) {
    let m: Vec<u8> = (0..77).map(|_| rand::random::<u8>()).collect();

    let hash = md.hash(&m);
    let hash2 = md.hash(&m);
    assert_eq!(hash[..], hash2[..]);

    md2.update(&m);
    md2.update(&m);
    let h = md2.finish(&[]);

    md3.update(&m);
    md3.update(&m);
    let h2 = md3.finish(&m);
    assert_ne!(h[..], h2[..]);
}

#[test]
fn test_unsupported_algorithm() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(EvercryptProvider::new());

    assert_eq!(registry.supports("unimplemented cipher"), false);
    let cipher_result = registry.get_aead("unimplemented cipher");
    assert_eq!(cipher_result.is_err(), true);
}

#[test]
fn test_aead() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(EvercryptProvider::new());
    assert!(registry.supports("AES-GCM-128"));

    // Get cipher through registry.
    let cipher_result = registry.get_aead("AES-GCM-128");
    assert!(cipher_result.is_ok());
    let cipher = match cipher_result {
        Ok(v) => v,
        Err(e) => panic!("Error getting AEAD {}", e),
    };
    aead_enc_dec(&cipher);

    // Get cipher through registry.
    let cipher_result = registry.get_aead("Chacha20Poly1305");
    assert!(cipher_result.is_ok());
    let cipher = match cipher_result {
        Ok(v) => v,
        Err(e) => panic!("Error getting AEAD {}", e),
    };
    aead_enc_dec(&cipher);

    // Remove all providers
    registry.clear();
    assert!(!registry.supports("Chacha20Poly1305"));

    // Add hacspec provider
    registry.add(HacspecProvider::new());
    assert!(registry.supports("Chacha20Poly1305"));

    let cipher_result = registry.get_aead("Chacha20Poly1305");
    assert!(cipher_result.is_ok());
    let cipher = match cipher_result {
        Ok(v) => v,
        Err(e) => panic!("Error getting AEAD {}", e),
    };
    aead_enc_dec(&cipher);
}

#[test]
fn test_message_digest_base() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(EvercryptProvider::new());
    assert!(registry.supports("SHA2-256"));

    // Get cipher through registry.
    let md_result = registry.get_digest("SHA2-256");
    assert_eq!(md_result.is_ok(), true);
    let md = match md_result.ok() {
        Some(v) => v,
        None => return,
    };
    let mut md2 = registry.get_digest("SHA2-256").unwrap();
    let mut md3 = registry.get_digest("SHA2-256").unwrap();
    md_test(&md, &mut md2, &mut md3);
}
