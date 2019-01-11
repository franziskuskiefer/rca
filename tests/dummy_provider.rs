extern crate rust_crypto;
use rust_crypto::cipher::*;
use rust_crypto::registry::*;

// TODO: ok?
use rand::Rng;
use std::collections::HashMap;

// A dummy provider to show how to implement one and test RCA.

// Symmetric cipher
struct DummySymmetricCipher {
    name: String,
    iv_len: usize,
    key_len: usize,
}

impl Algorithm for DummySymmetricCipher {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
}

impl SymmetricCipherOps for DummySymmetricCipher {
    fn new() -> Self {
        DummySymmetricCipher {
            name: "noop".to_string(),
            iv_len: 12,
            key_len: 128,
        }
    }
    fn get_instance(&self) -> Box<SymmetricCipherOps> {
        Box::new(Self {
            name: self.name.clone(),
            iv_len: self.iv_len,
            key_len: self.key_len,
        })
    }
    fn gen_key(&self) -> Vec<u8> {
        (0..self.key_len).map(|_| rand::random::<u8>()).collect()
    }
    fn gen_iv(&self) -> Vec<u8> {
        (0..self.iv_len).map(|_| rand::random::<u8>()).collect()
    }
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], m: &[u8]) -> Vec<u8> {
        m.to_vec()
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
        Ok(c.to_vec())
    }
}

// Asymmetric cipher
struct DummyAsymmetricCipher {
    name: String,
    nonce_len: usize,
}

impl Algorithm for DummyAsymmetricCipher {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
}

impl AsymmetricCipherOps for DummyAsymmetricCipher {
    fn new() -> Self {
        DummyAsymmetricCipher {
            name: "noop asym".to_string(),
            nonce_len: 128,
        }
    }
    fn get_instance(&self) -> Box<AsymmetricCipherOps> {
        Box::new(Self {
            name: self.name.clone(),
            nonce_len: self.nonce_len,
        })
    }
    fn gen_keypair(&self) -> KeyPair {
        let secret = (0..256).map(|_| rand::random::<u8>()).collect();
        let public = (0..256).map(|_| rand::random::<u8>()).collect();
        KeyPair {
            secret_bytes: secret,
            public_bytes: public,
        }
    }
    fn gen_nonce(&self) -> Vec<u8> {
        (0..self.nonce_len).map(|_| rand::random::<u8>()).collect()
    }
    fn encrypt(&self, key: &[u8], nonce: &[u8], m: &[u8]) -> Vec<u8> {
        m.to_vec()
    }
    fn decrypt(&self, key: &KeyPair, nonce: &[u8], c: &[u8]) -> Result<Vec<u8>, String> {
        Ok(c.to_vec())
    }
}

// The provider
pub struct DummyProvider {
    symmetric_ciphers: HashMap<String, Box<SymmetricCipherOps>>,
    asymmetric_ciphers: HashMap<String, Box<AsymmetricCipherOps>>,
}

impl DummyProvider {
    pub fn new() -> DummyProvider {
        let mut sym_cipher_map: HashMap<_, Box<SymmetricCipherOps>> = HashMap::new();
        let dummy_sym_cipher_factory = DummySymmetricCipher::new();
        sym_cipher_map.insert(
            dummy_sym_cipher_factory.get_name(),
            Box::new(dummy_sym_cipher_factory),
        );

        let mut asym_cipher_map: HashMap<_, Box<AsymmetricCipherOps>> = HashMap::new();
        let asym_cipher_map_factory = DummyAsymmetricCipher::new();
        asym_cipher_map.insert(
            asym_cipher_map_factory.get_name(),
            Box::new(asym_cipher_map_factory),
        );

        DummyProvider {
            symmetric_ciphers: sym_cipher_map,
            asymmetric_ciphers: asym_cipher_map,
        }
    }
}

impl DummyProvider {}

impl Provider for DummyProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        if let Some(_) = &self.symmetric_ciphers.get(&algorithm.to_string()) {
            return true;
        }
        if let Some(_) = &self.asymmetric_ciphers.get(&algorithm.to_string()) {
            return true;
        }
        false
    }
    fn get_sym_cipher(&self, algorithm: &'static str) -> Option<&Box<SymmetricCipherOps>> {
        self.symmetric_ciphers.get(&algorithm.to_string())
    }
    fn get_asym_cipher(&self, algorithm: &'static str) -> Option<&Box<AsymmetricCipherOps>> {
        self.asymmetric_ciphers.get(&algorithm.to_string())
    }
}
