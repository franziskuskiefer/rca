//! Rust crypto provider.
//! This is a crypto provider framework offers a unified, safe way of accessing
//! cryptographic implementations.
//!

pub mod aead;
pub mod digest;

pub mod registry;

// Some providers
pub mod provider;
