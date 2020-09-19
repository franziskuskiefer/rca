//! Message Digest
//! 

use crate::registry::Algorithm;

pub trait Digest: Algorithm {
    fn new() -> Self
    where
        Self: Sized;
    fn get_instance(&self) -> Box<dyn Digest>;

    // Single-shot hash function.
    fn hash(&self, message: &[u8]) -> Vec<u8>;

    // Streaming interface.
    fn update(&mut self, message: &[u8]);
    fn finish(&mut self, message: &[u8]) -> Vec<u8>;
}
