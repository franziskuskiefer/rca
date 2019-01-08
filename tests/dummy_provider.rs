extern crate rust_crypto;
// use rust_crypto::key::*;
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

pub struct DummyProvider {
    // TODO: remove?
    algorithms: Vec<String>,
    symmetric_ciphers: Vec<Box<SymmetricCipherOps>>
}

impl DummyProvider {
    pub fn new() -> DummyProvider {
        let dummy_cipher = Box::new(DummySymmetricCipher::new());
        DummyProvider {
            algorithms: vec![dummy_cipher.get_name()],
            symmetric_ciphers: vec![dummy_cipher]
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
    // fn get_sym_cipher(&mut self, algorithm: &'static str) -> Result<&Box<SymmetricCipherOps>, &'static str> {
    //     for algo in &self.symmetric_ciphers {
    //         if algo.get_name() == algorithm {
    //             return Ok(algo);
    //         }
    //     }
    //     return Err("This provider doesn't support the algorithm");
    // }
}
