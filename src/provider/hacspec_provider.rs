use hacspec_chacha20::{Key as HacspecKey, IV as HacspecNonce};
use hacspec_chacha20poly1305::{decrypt, encrypt};
use hacspec_lib::*;
use hacspec_poly1305::Tag as HacspecTag;

use std::collections::HashMap;

use crate::aead::{Aad, Aead as RcaAead, Ciphertext, Error, Key, Nonce, Tag};
use crate::digest::Digest as RcaDigest;
use crate::registry::*;

// Provider for Hacspec.
pub struct HacspecProvider {}

pub struct Chacha20Poly1305Provider {}

impl Algorithm for Chacha20Poly1305Provider {
    fn get_name() -> String {
        "Chacha20Poly1305".to_owned()
    }
}

impl RcaAead for Chacha20Poly1305Provider {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self {}
    }
    fn get_instance(&self) -> Box<dyn RcaAead> {
        Box::new(Self {})
    }

    // Nonce and key generation helper.
    fn key_gen(&self) -> Vec<u8> {
        unimplemented!()
    }
    fn get_key_len(&self) -> usize {
        32
    }
    fn nonce_gen(&self) -> Vec<u8> {
        unimplemented!()
    }
    fn get_nonce_len(&self) -> usize {
        12
    }

    // Single-shot encryption/decryption.
    fn encrypt(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &Aad,
        m: &[u8],
    ) -> Result<(Ciphertext, Tag), Error> {
        let (ctxt, tag) = encrypt(
            HacspecKey::from_public_slice(key),
            HacspecNonce::from_public_slice(nonce),
            &ByteSeq::from_public_slice(aad),
            &ByteSeq::from_public_slice(m),
        );
        unimplemented!()
    }

    fn decrypt(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &Aad,
        c: &Ciphertext,
        tag: &Tag,
    ) -> Result<Vec<u8>, String> {
        let (msg, valid) = decrypt(
            HacspecKey::from_public_slice(key),
            HacspecNonce::from_public_slice(nonce),
            &ByteSeq::from_public_slice(aad),
            &ByteSeq::from_public_slice(c),
            HacspecTag::from_native_slice(tag),
        );
        unimplemented!();
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

impl HacspecProvider {
    pub fn new() -> BaseProvider {
        let mut aead_map: HashMap<_, Box<dyn RcaAead>> = HashMap::new();
        aead_map.insert(
            "Chacha20Poly1305".to_owned(),
            Box::new(Chacha20Poly1305Provider::new()),
        );

        let digest_map: HashMap<_, Box<dyn RcaDigest>> = HashMap::new();

        BaseProvider::new(aead_map, digest_map)
    }
}
