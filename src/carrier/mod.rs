//! carrier/mod.rs - Esteganografía en recipientes y Ancla de Sigilo.

pub mod detector;
pub mod stego;

#[allow(unused_imports)]
pub use detector::{detect_format, find_legitimate_eof, CarrierFormat};
#[allow(unused_imports)]
pub use stego::{
    analyze_carrier, extract_from_carrier, hide_in_carrier, AnalysisReport,
};
