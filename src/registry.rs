//! The RCA registry that allows crypto providers to register their
//! implementations.
//!
//!
//! # TODO: Example

use crate::cipher::*;

pub trait Provider {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn get_sym_ciphers(&self) -> &Vec<Box<SymmetricCipherOps>>;
    fn get_asym_ciphers(&self) -> &Vec<Box<AsymmetricCipherOps>>;
}

pub trait Algorithm {
    fn get_name(&self) -> String;
}

pub struct Registry {
    providers: Vec<Box<Provider>>,
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
        return false;
    }
    pub fn get_symmetric_cipher(
        &mut self,
        algorithm: &'static str,
    ) -> Result<&Box<dyn SymmetricCipherOps + 'static>, &'static str> {
        for provider in &mut self.providers {
            let sym_ciphers = provider.get_sym_ciphers();
            for cipher in sym_ciphers {
                if cipher.get_name() == algorithm {
                    return Ok(cipher);
                }
            }
        }
        return Err("No provider attached that implements the cipher.");
    }
    pub fn get_asymmetric_cipher(
        &mut self,
        algorithm: &'static str,
    ) -> Result<&Box<dyn AsymmetricCipherOps + 'static>, &'static str> {
        for provider in &mut self.providers {
            let sym_ciphers = provider.get_asym_ciphers();
            for cipher in sym_ciphers {
                if cipher.get_name() == algorithm {
                    return Ok(cipher);
                }
            }
        }
        return Err("No provider attached that implements the cipher.");
    }
}
