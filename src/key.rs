
//! A key.
//! A key can either be a symmetric or an asymmetric key.
//!
//! # Symmtric keys
//!
//! # Asymmtric keys
//!
//! # TODO: Example

// #[derive(Debug)]
// enum KeyType {
//     Symmtric,
//     Asymmtric,
// }

// #[derive(Debug)]
// pub struct Key {
//     key_type: KeyType
// }

#[derive(Debug)]
pub enum SymKey<'a,T> {
    bytes (&'a[u8]),
    key (T),
}

pub trait SymmetricKeyOps<T> {
    fn new(&self, key_bytes: &[u8]) -> T;
}

pub trait AsymmetricKeyOps<T> {
    fn new(&self, secret: &[u8], public: &[u8]) -> T;
}

