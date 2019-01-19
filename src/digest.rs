//! A cipher.
//! A cipher can either be a symmetric or an asymmetric cipher.
//!
//! # Symmtric cipher
//!
//! # Asymmtric cipher
//!
//! # TODO: Example

use crate::registry::Algorithm;

pub trait MessageDigest: Algorithm {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<MessageDigest>;

    // One-shot hash function.
    fn hash(&self, message: &[u8]) -> Vec<u8>;

    // Streaming interface.
    fn update(&mut self, message: &[u8]);
    fn finish(&mut self, message: Option<&[u8]>) -> Vec<u8>;
}
