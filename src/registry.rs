//! The RCA registry that allows crypto providers to register their
//! implementations.
//!
//!
//! # TODO: Example

use crate::aead::*;
use crate::digest::*;

use std::collections::HashMap;

/// A crypto library that wants to register with the `Registry` has to implement
/// this `Provider` trait.
pub trait Provider {
    fn supports(&self, algorithm: &'static str) -> bool;
    fn get_aead(&self, algorithm: &'static str) -> Option<&Box<dyn Aead>>;
    fn get_digest(&self, algorithm: &'static str) -> Option<&Box<dyn Digest>>;
}

/// A basic implementation of a provider that can be used for convenience.
pub struct BaseProvider {
    aead_map: HashMap<String, Box<dyn Aead>>,
    digest_map: HashMap<String, Box<dyn Digest>>,
}

impl BaseProvider {
    /// Create a new Provider with the given AEADs.
    pub fn new(
        aead_map: HashMap<String, Box<dyn Aead>>,
        digest_map: HashMap<String, Box<dyn Digest>>,
    ) -> BaseProvider {
        Self {
            aead_map,
            digest_map,
        }
    }
}

impl Provider for BaseProvider {
    fn supports(&self, algorithm: &'static str) -> bool {
        if self.get_aead(&algorithm).is_some() {
            return true;
        }
        if self.get_digest(&algorithm).is_some() {
            return true;
        }
        false
    }
    fn get_aead(&self, algorithm: &'static str) -> Option<&Box<dyn Aead>> {
        self.aead_map.get(&algorithm.to_string())
    }
    fn get_digest(&self, algorithm: &'static str) -> Option<&Box<dyn Digest>> {
        self.digest_map.get(&algorithm.to_string())
    }
}

/// The basic trait implemented by all primitives.
pub trait Algorithm {
    fn get_name() -> String
    where
        Self: Sized;
}

/// The `Registry` holding all providers.
#[derive(Default)]
pub struct Registry {
    providers: Vec<Box<dyn Provider>>,
}

macro_rules! get_algorithm {
    ( $( $name:ident => $ty:ty ; )* ) => {
        $(
            pub fn $name(&self, algorithm: &'static str) -> Result<Box<$ty>, &'static str> {
                for provider in &self.providers {
                    if let Some(c) = provider.$name(algorithm) {
                        return Ok(c.get_instance());
                    }
                }
                Err("Unsupported algorithm")
            }
        )*
    };
}

impl Registry {
    /// Initialise the `Registry`.
    pub fn new() -> Registry {
        Registry {
            providers: Vec::new(),
        }
    }

    /// Add a new provider to the `Registry`.
    pub fn add<T: Provider + 'static>(&mut self, provider: T) {
        self.providers.push(Box::new(provider));
    }

    /// Remove all providers from the `Registry`.
    pub fn clear(&mut self) {
        self.providers.clear();
    }

    /// Check support for an `algorithm`.
    /// Returns `true` if a `Provider` is registered that supports the `algorithm`.
    pub fn supports(&mut self, algorithm: &'static str) -> bool {
        for provider in &mut self.providers {
            if provider.supports(&algorithm) {
                return true;
            }
        }
        false
    }

    // Define convenience functions to get an algorithm implementation.
    get_algorithm! {
        get_aead => dyn Aead;
        get_digest => dyn Digest;
    }
}
