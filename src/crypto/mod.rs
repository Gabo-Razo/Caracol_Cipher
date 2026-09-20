//! crypto/mod.rs - Primitivas criptográficas 100% nativas en Rust puro.

pub mod sha256;
pub mod hmac;
pub mod mem;
pub mod rand;
pub mod kdf;
pub mod sbox;

#[allow(unused_imports)]
pub use sha256::{sha256_digest, Sha256};
pub use hmac::{hmac_sha256, constant_time_eq};
#[allow(unused_imports)]
pub use mem::{SecureBuffer, SecureKey, zeroize_slice};
#[allow(unused_imports)]
pub use rand::{fill_secure_random, random_16, random_32, DeterministicPrng};
pub use kdf::{derive_session_keys, pbkdf2_sha256, SessionKeys};
pub use sbox::DynamicSBox;
