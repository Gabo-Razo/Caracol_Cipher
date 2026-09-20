//! cli/mod.rs - Interfaz de línea de comandos de Caracol Cipher.

pub mod args;
pub mod commands;

pub use args::{CliParser, SubCommand};
pub use commands::{
    exec_analyze, exec_extract, exec_hide, exec_keygen, exec_open, exec_seal,
};
