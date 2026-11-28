//! Top‑level module for the Red‑Team hardware security toolkit.

pub mod discovery;
pub mod driver;
#[cfg(feature = "asm")]
pub mod asm_payload;
pub mod analysis;
pub mod rf_scan;
pub mod pentest;
pub mod report;
pub mod cli;

pub use discovery::*;
pub use driver::*;
#[cfg(feature = "asm")]
pub use asm_payload::*;
pub use analysis::*;
pub use rf_scan::*;
pub use pentest::*;
pub use report::*;
pub use cli::*;
