//! The RCA registry that allows crypto providers to register their
//! implementations.
//!
//!
//! # TODO: Example

use crate::cipher::*;

pub trait Provider {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn get_symmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<SymmetricCipherOps>>;
    fn get_asymmetric_cipher(&self, algorithm: &'static str) -> Option<&Box<AsymmetricCipherOps>>;
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
    }
}
