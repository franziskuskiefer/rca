
//! A cipher.
//! A cipher can either be a symmetric or an asymmetric cipher.
//!
//! # Symmtric cipher
//!
//! # Asymmtric cipher
//!
//! # TODO: Example

use crate::key::SymKey;
use crate::registry::Algorithm;

// #[derive(Debug)]
// pub struct SymmetricCipher {
// }

// impl SymmetricCipher {
//     fn new(name: &'static str) -> impl SymmetricCipherOps {
//         unimplemented!();
//     }
// }

// A Ciphertext consists of the following elements:
// c:  encrypted data (mandatory)
// t:  authentication data, e.g. tag (Option)
// iv: initialisation vector (Option)
#[derive(Debug,PartialEq)]
pub struct Ciphertext {
    c: Vec<u8>,
    t: Option<Vec<u8>>,
    iv: Option<Vec<u8>>
}

impl Ciphertext {
    pub fn new(c: &[u8]) -> Ciphertext {
        Ciphertext {
            c: c.to_vec(),
            t: None,
            iv: None
        }
    }
    pub fn set_t(&mut self, tag: &[u8]) -> &Ciphertext {
        self.t = Some(tag.to_vec());
        self
    }
    pub fn set_iv(&mut self, iv: &[u8]) -> &Ciphertext {
        self.iv = Some(iv.to_vec());
        self
    }
    pub fn get_c(&self) -> &Vec<u8> {
        &self.c
    }
    pub fn get_t(&self) -> &Option<Vec<u8>> {
        &self.t
    }
    pub fn get_iv(&self) -> &Option<Vec<u8>> {
        &self.iv
    }
}

pub trait SymmetricCipherOps: Algorithm {
    fn new() -> Self where Self: Sized;
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], m: &[u8]) -> Ciphertext;
    fn decrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], c: &[u8]) -> Result<Vec<u8>, String>;
}

pub trait AsymmetricCipherOps: Algorithm {
    fn new() -> Self where Self: Sized;
    fn encrypt(&self, key: &[u8], iv: &[u8], aad: &[u8], m: &[u8]) -> Ciphertext;
}

