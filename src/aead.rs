//! AEADs
//!

use crate::registry::Algorithm;

pub type Ciphertext = Vec<u8>;
pub type Tag = Vec<u8>;
pub type Nonce = [u8];
pub type Aad = [u8];
pub type Key = [u8];

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidInit = 0,
    InvalidAlgorithm = 1,
    InvalidCiphertext = 2,
    InvalidNonce = 3,
    UnsupportedConfig = 4,
    Encrypting = 5,
    Decrypting = 6,
}

pub trait Aead: Algorithm {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<dyn Aead>;

    // Nonce and key generation helper.
    fn key_gen(&self) -> Vec<u8>;
    fn get_key_len(&self) -> usize;
    fn nonce_gen(&self) -> Vec<u8>;
    fn get_nonce_len(&self) -> usize;

    // Single-shot encryption/decryption.
    fn encrypt(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &Aad,
        m: &[u8],
    ) -> Result<(Ciphertext, Tag), Error>;
    fn decrypt(
        &self,
        key: &Key,
        nonce: &Nonce,
        aad: &Aad,
        c: &Ciphertext,
        tag: &Tag,
    ) -> Result<Vec<u8>, String>;

    // // Streaming interface.
    // // Note that aad might only be needed in finish for some ciphers but earlier for others.
    // // Hence it's required in init.
    // fn init(&mut self, key: &Key, nonce: &Nonce, aad: &Aad);
    // fn update(&mut self, m: &[u8]);
    // fn finish(&mut self, m: &[u8]) -> Result<Vec<u8>, String>;
}
