extern crate rust_crypto;
use rust_crypto::key::*;
use rust_crypto::cipher::*;
use rust_crypto::registry::*;

// Dummy implementation of RCA.

// #[derive(Debug)]
// struct DummySymmetricKey {
//     bytes: Vec<u8>
// }

// impl SymmetricKeyOps<DummySymmetricKey> for DummySymmetricKey {
//     fn new(&self, key_bytes: &[u8]) -> DummySymmetricKey {
//         DummySymmetricKey {
//             bytes: key_bytes.to_vec(),
//         }
//     }
// }

struct DummySymmetricCipher {
    name: &'static str
}

impl Algorithm for DummySymmetricCipher {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
}

impl SymmetricCipherOps for DummySymmetricCipher {
    fn new() -> DummySymmetricCipher {
        DummySymmetricCipher {
            name: "noop"
        }
    }
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], m: &[u8]) -> Ciphertext {
        Ciphertext::new(m)
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
        Ok(c.to_vec())
    }
}

#[derive(Debug)]
struct DummyProvider {
    algorithms: Vec<&'static str>
}

impl DummyProvider {
    fn new() -> DummyProvider {
        DummyProvider {
            algorithms: vec!["AES", "ChaCha20Poly1305"]
        }
    }
}

impl Provider for DummyProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        self.algorithms.contains(&algorithm)
    }
    fn get_algorithms(&self) -> Vec<Box<Algorithm>> {
        vec![Box::new(DummySymmetricCipher::new())]
    }
    fn get_algorithm(&self, algorithm: &'static str) -> Box<(dyn SymmetricCipherOps + 'static)> {
        Box::new(DummySymmetricCipher::new())
    }
}


use rand::Rng;

fn enc_dec_test(cipher: Box<SymmetricCipherOps>) {
    let cipher = DummySymmetricCipher::new();
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
fn test_encrypt_decrypt() {
    let cipher = DummySymmetricCipher::new();
    enc_dec_test(Box::new(cipher));
}

#[test]
fn test_provider() {
    // Register provider
    let mut registry = Registry::new();
    registry.add(DummyProvider::new());
    assert_eq!(registry.supports("AES"), true);

    // Get cipher through registry.
    let cipher_result = registry.get_symmetric_cipher("AES");
    assert_eq!(cipher_result.is_ok(), true);
    let cipher = match cipher_result.ok() {
        Some(v) => v,
        None => return,
    };
    enc_dec_test(cipher);
}

