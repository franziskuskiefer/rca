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
    fn gen_key(&self) -> Vec<u8>;
    fn gen_iv(&self) -> Vec<u8>;
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], m: &[u8]) -> Vec<u8>;
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], c: &[u8]) -> Result<Vec<u8>, String>;
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
