extern crate rust_crypto;
// use rust_crypto::key::*;
use rust_crypto::cipher::*;
use rust_crypto::registry::*;

// TODO: ok?
use rand::Rng;

// Dummy implementation of RCA.

// Symmetric cipher
struct DummySymmetricCipher {
    name: &'static str,
    iv_len: usize,
    key_len: usize,
}

impl Algorithm for DummySymmetricCipher {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
}

impl SymmetricCipherOps for DummySymmetricCipher {
    fn new() -> DummySymmetricCipher {
        DummySymmetricCipher {
            name: "noop",
            iv_len: 12,
            key_len: 128,
        }
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
    name: &'static str,
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
            name: "noop asym",
            nonce_len: 128,
        }
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
    // TODO: remove?
    algorithms: Vec<String>,
    symmetric_ciphers: Vec<Box<SymmetricCipherOps>>,
    asymmetric_ciphers: Vec<Box<AsymmetricCipherOps>>,
}

impl DummyProvider {
    pub fn new() -> DummyProvider {
        let dummy_cipher = Box::new(DummySymmetricCipher::new());
        let dummy_acipher = Box::new(DummyAsymmetricCipher::new());
        DummyProvider {
            algorithms: vec![dummy_cipher.get_name(), dummy_acipher.get_name()],
            symmetric_ciphers: vec![dummy_cipher],
            asymmetric_ciphers: vec![dummy_acipher],
        }
    }
}

impl Provider for DummyProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        self.algorithms.contains(&algorithm.to_string())
    }
    fn get_sym_ciphers(&self) -> &Vec<Box<SymmetricCipherOps>> {
        &self.symmetric_ciphers
    }
    fn get_asym_ciphers(&self) -> &Vec<Box<AsymmetricCipherOps>> {
        &self.asymmetric_ciphers
    }
}
