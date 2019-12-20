extern crate rca;
use rca::cipher::*;
use rca::digest::*;
use rca::registry::*;

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

impl SymmetricCipher for DummySymmetricCipher {
    fn new() -> Self {
        DummySymmetricCipher {
            name: "noop".to_string(),
            iv_len: 12,
            key_len: 128,
        }
    }
    fn get_instance(&self) -> Box<SymmetricCipher> {
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
    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        m: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let iv_out = if iv.is_some() {
            iv.unwrap().to_vec()
        } else {
            (0..self.iv_len).map(|_| rand::random::<u8>()).collect()
        };
        (m.to_vec(), iv_out)
    }
    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: Option<&[u8]>,
        c: &[u8],
    ) -> Result<Vec<u8>, String> {
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

impl AsymmetricCipher for DummyAsymmetricCipher {
    fn new() -> Self {
        DummyAsymmetricCipher {
            name: "noop asym".to_string(),
            nonce_len: 128,
        }
    }
    fn get_instance(&self) -> Box<AsymmetricCipher> {
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

// Message digest
struct DummyMessageDigest {
    name: String,
    out_len: usize,
    state: [u8; 32],
}

impl Algorithm for DummyMessageDigest {
    fn get_name(&self) -> String {
        self.name.to_string()
    }
}

impl MessageDigest for DummyMessageDigest {
    fn new() -> Self {
        Self {
            name: "stupid digest".to_string(),
            out_len: 32,
            state: [0; 32],
        }
    }
    fn get_instance(&self) -> Box<MessageDigest> {
        Box::new(Self {
            name: self.name.clone(),
            out_len: self.out_len,
            state: self.state,
        })
    }
    fn hash(&self, message: &[u8]) -> Vec<u8> {
        message.iter().map(|x| !x).collect()
    }
    fn update(&mut self, message: &[u8]) {
        for (i, b) in message.iter().enumerate() {
            if i >= self.state.len() {
                break;
            }
            self.state[i] ^= b;
        }
    }
    fn finish(&mut self, message: Option<&[u8]>) -> Vec<u8> {
        if message.is_some() {
            self.update(message.unwrap());
        }
        self.state.to_vec()
    }
}

// The provider
pub struct DummyProvider {
    symmetric_ciphers: HashMap<String, Box<SymmetricCipher>>,
    asymmetric_ciphers: HashMap<String, Box<AsymmetricCipher>>,
    message_digests: HashMap<String, Box<MessageDigest>>,
}

impl DummyProvider {
    pub fn new() -> DummyProvider {
        let mut sym_cipher_map: HashMap<_, Box<SymmetricCipher>> = HashMap::new();
        let dummy_sym_cipher_factory = DummySymmetricCipher::new();
        sym_cipher_map.insert(
            dummy_sym_cipher_factory.get_name(),
            Box::new(dummy_sym_cipher_factory),
        );

        let mut asym_cipher_map: HashMap<_, Box<AsymmetricCipher>> = HashMap::new();
        let asym_cipher_map_factory = DummyAsymmetricCipher::new();
        asym_cipher_map.insert(
            asym_cipher_map_factory.get_name(),
            Box::new(asym_cipher_map_factory),
        );

        let mut md_map: HashMap<_, Box<MessageDigest>> = HashMap::new();
        let md_map_factory = DummyMessageDigest::new();
        md_map.insert(md_map_factory.get_name(), Box::new(md_map_factory));

        DummyProvider {
            symmetric_ciphers: sym_cipher_map,
            asymmetric_ciphers: asym_cipher_map,
            message_digests: md_map,
        }
    }
}

impl Provider for DummyProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        if self.symmetric_ciphers.get(&algorithm.to_string()).is_some() {
            return true;
        }
        if self
            .asymmetric_ciphers
            .get(&algorithm.to_string())
            .is_some()
        {
            return true;
        }
        if self.message_digests.get(&algorithm.to_string()).is_some() {
            return true;
        }
        false
    }
    fn get_symmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<SymmetricCipher>> {
        self.symmetric_ciphers.get(&algorithm.to_string())
    }
    fn get_asymmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<AsymmetricCipher>> {
        self.asymmetric_ciphers.get(&algorithm.to_string())
    }
    fn get_messagedigest(&self, algorithm: &'static str) -> Option<&Box<MessageDigest>> {
        self.message_digests.get(&algorithm.to_string())
    }
}

// Second dummy provider using the BaseProvider.
// Using the same dummy algorithm implementations.
pub struct TestBaseProvider {}

impl TestBaseProvider {
    pub fn new() -> BaseProvider {
        let mut sym_cipher_map: HashMap<_, Box<SymmetricCipher>> = HashMap::new();
        let dummy_sym_cipher_factory = DummySymmetricCipher::new();
        sym_cipher_map.insert(
            dummy_sym_cipher_factory.get_name(),
            Box::new(dummy_sym_cipher_factory),
        );

        let mut asym_cipher_map: HashMap<_, Box<AsymmetricCipher>> = HashMap::new();
        let asym_cipher_map_factory = DummyAsymmetricCipher::new();
        asym_cipher_map.insert(
            asym_cipher_map_factory.get_name(),
            Box::new(asym_cipher_map_factory),
        );

        let mut md_map: HashMap<_, Box<MessageDigest>> = HashMap::new();
        let md_map_factory = DummyMessageDigest::new();
        md_map.insert(md_map_factory.get_name(), Box::new(md_map_factory));

        BaseProvider::new(sym_cipher_map, asym_cipher_map, md_map)
    }
}
