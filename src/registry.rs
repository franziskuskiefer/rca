//! The RCA registry that allows crypto providers to register their
//! implementations.
//!
//!
//! # TODO: Example

use crate::cipher::*;
use crate::digest::*;

use std::collections::HashMap;

pub trait Provider {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn get_symmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<SymmetricCipherOps>>;
    fn get_asymmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<AsymmetricCipherOps>>;
    fn get_messagedigest(&self, algorithm: &'static str) -> Option<&Box<MessageDigest>>;
}

pub struct BaseProvider {
    symmetric_ciphers: HashMap<String, Box<SymmetricCipherOps>>,
    asymmetric_ciphers: HashMap<String, Box<AsymmetricCipherOps>>,
    message_digests: HashMap<String, Box<MessageDigest>>,
}

impl BaseProvider {
    pub fn new(
        sym_cipher_map: HashMap<String, Box<SymmetricCipherOps>>,
        asym_cipher_map: HashMap<String, Box<AsymmetricCipherOps>>,
        md_map: HashMap<String, Box<MessageDigest>>,
    ) -> BaseProvider {
        BaseProvider {
            symmetric_ciphers: sym_cipher_map,
            asymmetric_ciphers: asym_cipher_map,
            message_digests: md_map,
        }
    }
}

impl Provider for BaseProvider {
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
    fn get_symmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<SymmetricCipherOps>> {
        self.symmetric_ciphers.get(&algorithm.to_string())
    }
    fn get_asymmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<AsymmetricCipherOps>> {
        self.asymmetric_ciphers.get(&algorithm.to_string())
    }
    fn get_messagedigest(&self, algorithm: &'static str) -> Option<&Box<MessageDigest>> {
        self.message_digests.get(&algorithm.to_string())
    }
}

pub trait Algorithm {
    fn get_name(&self) -> String;
}

#[derive(Default)]
pub struct Registry {
    providers: Vec<Box<Provider>>,
}

macro_rules! get_algorithm {
    ( $( $name:ident => $ty:ty ; )* ) => {
        $(
            pub fn $name(&mut self, algorithm: &'static str) -> Result<Box<$ty>, &'static str> {
                for provider in &mut self.providers {
                    if let Some(c) = provider.$name(algorithm) {
                        return Ok(c.get_instance());
                    }
                }
                Err("No provider attached that implements the cipher.")
            }
        )*
    };
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            providers: Vec::new(),
        }
    }
    pub fn add<T: Provider + 'static>(&mut self, provider: T) {
        self.providers.push(Box::new(provider));
    }
    pub fn supports(&mut self, algorithm: &'static str) -> bool {
        for provider in &mut self.providers {
            if provider.supports(&algorithm) {
                return true;
            }
        }
        false
    }
    get_algorithm! {
        get_symmetric_cipher => SymmetricCipherOps;
        get_asymmetric_cipher => AsymmetricCipherOps;
        get_messagedigest => MessageDigest;
    }
}
