use evercrypt::prelude::*;

use std::collections::HashMap;

use crate::aead::{Aad, Aead as RcaAead, Ciphertext, Error, Key, Nonce, Tag};
use crate::digest::Digest as RcaDigest;
use crate::registry::*;

// Provider for Evercrypt.
pub struct EvercryptProvider {}

macro_rules! implement_aead {
    ($provider_name:ident, $string_id:literal, $mode:expr) => {
        pub struct $provider_name {
            mode: AeadMode,
            nonce_len: usize,
        }

        impl Algorithm for $provider_name {
            fn get_name() -> String {
                $string_id.to_owned()
            }
        }

        impl RcaAead for $provider_name {
            fn new() -> Self
            where
                Self: Sized,
            {
                Self {
                    mode: $mode,
                    nonce_len: 12,
                }
            }
            fn get_instance(&self) -> Box<dyn RcaAead> {
                Box::new(Self {
                    mode: $mode,
                    nonce_len: 12,
                })
            }

            // Nonce and key generation helper.
            fn key_gen(&self) -> Vec<u8> {
                aead_key_gen(self.mode)
            }
            fn get_key_len(&self) -> usize {
                aead_key_size(&self.mode)
            }
            fn nonce_gen(&self) -> Vec<u8> {
                aead_nonce_gen(self.mode).to_vec()
            }
            fn get_nonce_len(&self) -> usize {
                self.nonce_len
            }

            // Single-shot encryption/decryption.
            fn encrypt(
                &self,
                key: &Key,
                nonce: &Nonce,
                aad: &Aad,
                m: &[u8],
            ) -> Result<(Ciphertext, Tag), Error> {
                let mut n = [0u8; 12];
                n.clone_from_slice(nonce);
                let (ctxt, tag) = Aead::new(self.mode, key)
                    .unwrap()
                    .encrypt(m, &n, aad)
                    .unwrap();
                Ok((ctxt, tag.to_vec()))
            }

            fn decrypt(
                &self,
                key: &Key,
                nonce: &Nonce,
                aad: &Aad,
                c: &Ciphertext,
                tag: &Tag,
            ) -> Result<Vec<u8>, String> {
                let mut n = [0u8; 12];
                n.clone_from_slice(nonce);
                let ctxt = match Aead::new(self.mode, key).unwrap().decrypt(c, tag, &n, aad) {
                    Ok(c) => c,
                    Err(e) => return Err(format!("Error: {:?}", e)),
                };
                Ok(ctxt)
            }

            fn init(&mut self, _key: &Key, _nonce: &Nonce, _aad: &Aad) {
                unimplemented!();
            }
            fn update(&mut self, _m: &[u8]) {
                unimplemented!();
            }
            fn finish(&mut self, _m: &[u8]) -> Result<Vec<u8>, String> {
                unimplemented!();
            }
        }
    };
}

implement_aead!(AesGcm128Provider, "AES-GCM-128", AeadMode::Aes128Gcm);
implement_aead!(AesGcm256Provider, "AES-GCM-256", AeadMode::Aes128Gcm);
implement_aead!(
    Chacha20Poly1305Provider,
    "Chacha20Poly1305",
    AeadMode::Chacha20Poly1305
);

macro_rules! implement_digest {
    ($provider_name:ident, $string_id:literal, $mode:expr) => {
        pub struct $provider_name {
            digest: Option<Digest>,
        }

        impl Algorithm for $provider_name {
            fn get_name() -> String {
                $string_id.to_owned()
            }
        }

        impl RcaDigest for $provider_name {
            fn new() -> Self
            where
                Self: Sized,
            {
                Self { digest: None }
            }
            fn get_instance(&self) -> Box<dyn RcaDigest> {
                Box::new(Self {
                    digest: Some(Digest::new($mode).unwrap()),
                })
            }

            // Single-shot hash function.
            fn hash(&self, message: &[u8]) -> Vec<u8> {
                hash($mode, message)
            }

            // Streaming interface.
            fn update(&mut self, message: &[u8]) {
                self.digest.as_mut().unwrap().update(message).unwrap();
            }
            fn finish(&mut self, message: &[u8]) -> Vec<u8> {
                if !message.is_empty() {
                    self.digest.as_mut().unwrap().update(message).unwrap();
                }
                self.digest.as_mut().unwrap().finish().unwrap()
            }
        }
    };
}

implement_digest!(Sha256Provider, "SHA2-256", DigestMode::Sha256);
implement_digest!(Sha384Provider, "SHA2-384", DigestMode::Sha384);
implement_digest!(Sha512Provider, "SHA2-512", DigestMode::Sha512);

impl EvercryptProvider {
    pub fn new() -> BaseProvider {
        let mut aead_map: HashMap<_, Box<dyn RcaAead>> = HashMap::new();
        aead_map.insert("AES-GCM-128".to_owned(), Box::new(AesGcm128Provider::new()));
        aead_map.insert("AES-GCM-256".to_owned(), Box::new(AesGcm256Provider::new()));
        aead_map.insert(
            "Chacha20Poly1305".to_owned(),
            Box::new(Chacha20Poly1305Provider::new()),
        );

        let mut digest_map: HashMap<_, Box<dyn RcaDigest>> = HashMap::new();
        digest_map.insert("SHA2-256".to_owned(), Box::new(Sha256Provider::new()));
        digest_map.insert("SHA2-384".to_owned(), Box::new(Sha384Provider::new()));
        digest_map.insert("SHA2-512".to_owned(), Box::new(Sha512Provider::new()));

        BaseProvider::new(aead_map, digest_map)
    }
}
