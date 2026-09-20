//! engine/mod.rs - Motor geométrico Caracol y orquestación del cifrado SPN.

pub mod spiral;
pub mod decoys;
pub mod pipeline;
pub mod visualizer;

#[allow(unused_imports)]
pub use spiral::SnailSpiral;
pub use decoys::DecoyLabyrinth;
pub use pipeline::{encrypt_block, decrypt_block, DecryptedPayload};
pub use visualizer::{render_decrypt_animation, render_encrypt_animation};
