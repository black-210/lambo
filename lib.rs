//! hw_toolkit – Full Red‑Team Hardware Security Platform
//!
//! Modules:
//! - `discovery`         Passive device enumeration (USB, Serial, JTAG)
//! - `driver`            HardwareCaptureSource trait + mock driver
//! - `asm_payload`       Low-level x86_64/ARM64 inline ASM primitives
//! - `physical_analysis` MAD/CUSUM/TVLA/NICV/SNR/CPA/Template-Attack/EM models
//! - `em_nuclear`        Maxwell/Faraday/HEMP/TEMPEST & Nuclear SEU/SEL/TID models
//! - `vuln_db`           Hardware vulnerability database (Physical/RF/EM/Rad/Arch)
//! - `pentest`           Full pentest plan DSL + executor + result reporting
//! - `rf_scan`           RF spectrum analysis, demodulation, jamming/replay detection
//! - `report`            HTML/JSON/Markdown/PDF report generation

pub mod discovery;
pub mod driver;
pub mod asm_payload;
pub mod physical_analysis;
pub mod em_nuclear;
pub mod vuln_db;
pub mod pentest;
pub mod rf_scan;
pub mod report;

pub use discovery::*;
pub use driver::*;
pub use asm_payload::*;
pub use physical_analysis::*;
pub use em_nuclear::*;
pub use vuln_db::*;
pub use pentest::*;
pub use rf_scan::*;
pub use report::*;
