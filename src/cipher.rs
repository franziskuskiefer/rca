//! A cipher.
//! A cipher can either be a symmetric or an asymmetric cipher.
//!
//! # Symmtric cipher
//!
//! # Asymmtric cipher
//!
//! # TODO: Example

use crate::registry::Algorithm;

pub trait SymmetricCipher: Algorithm {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<SymmetricCipher>;

    // IV and key generation helper.
    fn gen_key(&self) -> Vec<u8>;
    fn gen_iv(&self) -> Vec<u8>;

    // One-shot encryption/decryption.
    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        aad: Option<&[u8]>,
        m: &[u8],
    ) -> (Vec<u8>, Vec<u8>);
    fn decrypt(
        &self,
        key: &[u8],
        iv: &[u8],
        aad: Option<&[u8]>,
        c: &[u8],
    ) -> Result<Vec<u8>, String>;

    // Streaming interface.
    // Note that aad might only be needed in finish for some ciphers but earlier for others.
    // Hence it's required in init.
    // fn init(&mut self, key: &[u8], iv: Option<&[u8]>, aad: Option<&[u8]>);
    // fn update(&mut self, m: &[u8]) -> Result<Vec<u8>, String>;
    // fn finish(&mut self, m: Option<&[u8]>) -> Result<Vec<u8>, String>;
}

#[derive(Debug, PartialEq)]
pub struct KeyPair {
    pub public_bytes: Vec<u8>,
    pub secret_bytes: Vec<u8>,
}

pub trait AsymmetricCipher: Algorithm {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<AsymmetricCipher>;
    fn gen_keypair(&self) -> KeyPair;
    fn gen_nonce(&self) -> Vec<u8>;
    fn encrypt(&self, key: &[u8], nonce: &[u8], m: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &KeyPair, nonce: &[u8], m: &[u8]) -> Result<Vec<u8>, String>;
}
