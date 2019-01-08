
//! The RCA registry that allows crypto providers to register their
//! implementations.
//!
//!
//! # TODO: Example

use crate::cipher::*;

pub trait Provider {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn get_algorithms(&self) -> Vec<Box<Algorithm>>;
    fn get_algorithm(&self, algorithm: &'static str) -> Box<SymmetricCipherOps>;
}

pub trait Algorithm {
    fn get_name(&self) -> String;
}

pub struct Registry {
    providers: Vec<Box<Provider>>
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            providers: Vec::new()
        }
    }
    pub fn add<T:Provider + 'static>(&mut self, provider: T) {
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
    pub fn get_symmetric_cipher(&mut self, algorithm: &'static str) -> Result<Box<dyn SymmetricCipherOps + 'static>, &'static str> {
        for provider in &mut self.providers {
            if provider.supports(&algorithm) {
                return Ok(provider.get_algorithm(algorithm));
            }
        }
        return Err("No provider attached that implements the cipher.");   
    }
}
