//! # IQ Research Workbench
//!
//! A comprehensive offline-first, authorized hardware security assessment platform
//! combining IQ signal screening, physical side-channel analysis, firmware inspection,
//! cryptanalysis research, protocol analysis, evidence integrity, and educational
//! quantum simulation — usable both as a **CLI tool** and a **Rust library**.
//!
//! ## Quick Library Usage
//! ```no_run
//! use iq_research_workbench::prelude::*;
//! use std::path::Path;
//!
//! let iq = Workbench::new()
//!     .sample_rate(2_000_000.0)
//!     .analyze_iq_file(Path::new("capture.csv"))?;
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod ai;
pub mod assess;
pub mod audit;
pub mod common;
pub mod cryptanalysis;
pub mod evidence;
pub mod firmware;
pub mod gui;
pub mod legal;
pub mod physical;
pub mod protocol;
pub mod quantum;
pub mod signal;

pub use assess::{
    AssessmentInput, assess_engagement, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace,
};
pub use audit::{audit_to_sarif, scan_for_issues, scan_source_tree};
pub use cryptanalysis::{aes_ctr_reuse, coppersmith_stub, rsa_factor, frequency_analysis,
    entropy_score, vigenere_crack, xor_key_recovery};
pub use evidence::{create_manifest, verify_manifest};
pub use firmware::inspect_firmware_binary;
pub use gui::launch_gui;
pub use legal::{
    AuditLedgerEntry, AuthorizationScope, append_audit_entry, create_scope_file,
    verify_audit_ledger, verify_scope_file,
};
pub use physical::analyze_trace;
pub use protocol::{analyze_protocol_capture, detect_anomalies as detect_protocol_anomalies};
pub use quantum::simulate_qubit;
pub use signal::{analyze_iq, analyze_samples};

use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

// ─── Workbench Builder ───────────────────────────────────────────────────────

/// Ergonomic high-level façade for using the workbench as a Rust library.
///
/// # Examples
/// ```no_run
/// use iq_research_workbench::Workbench;
/// use std::path::Path;
///
/// let wb = Workbench::new()
///     .sample_rate(1_000_000.0)
///     .physical_threshold(5.0);
///
/// let iq_report = wb.analyze_iq_file(Path::new("capture.csv"))?;
/// let phys_report = wb.analyze_physical_trace(Path::new("trace.csv"), None)?;
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct Workbench {
    sample_rate_hz: Option<f64>,
    physical_threshold: f64,
    scope_file: Option<PathBuf>,
    ledger_file: Option<PathBuf>,
}

impl Default for Workbench {
    fn default() -> Self {
        Self::new()
    }
}

impl Workbench {
    pub fn new() -> Self {
        Self {
            sample_rate_hz: None,
            physical_threshold: 6.0,
            scope_file: None,
            ledger_file: None,
        }
    }

    pub fn sample_rate(mut self, hz: f64) -> Self {
        self.sample_rate_hz = Some(hz);
        self
    }

    pub fn physical_threshold(mut self, threshold: f64) -> Self {
        self.physical_threshold = threshold;
        self
    }

    pub fn with_scope(mut self, scope_file: impl AsRef<Path>) -> Self {
        self.scope_file = Some(scope_file.as_ref().to_path_buf());
        self
    }

    pub fn with_ledger(mut self, ledger_file: impl AsRef<Path>) -> Self {
        self.ledger_file = Some(ledger_file.as_ref().to_path_buf());
        self
    }

    pub fn analyze_iq_file(&self, path: &Path) -> Result<Value> {
        analyze_iq(path, self.sample_rate_hz)
    }

    pub fn analyze_physical_trace(
        &self,
        trace: &Path,
        reference: Option<&Path>,
    ) -> Result<Value> {
        analyze_trace(trace, reference, self.physical_threshold)
    }

    pub fn audit_hardware_source(&self, root: &Path) -> Result<Value> {
        scan_source_tree(root)
    }

    pub fn inspect_firmware(&self, firmware_path: &Path) -> Result<Value> {
        inspect_firmware_binary(firmware_path)
    }

    /// Run a full assessment across IQ, physical, and source modules.
    pub fn assess(
        &self,
        iq_file: Option<&Path>,
        physical_trace: Option<&Path>,
        physical_reference: Option<&Path>,
        source_dir: Option<&Path>,
    ) -> Result<Value> {
        assess_engagement(&AssessmentInput {
            iq_file: iq_file.map(Path::to_path_buf),
            sample_rate_hz: self.sample_rate_hz,
            physical_trace: physical_trace.map(Path::to_path_buf),
            physical_reference: physical_reference.map(Path::to_path_buf),
            physical_threshold: self.physical_threshold,
            source_dir: source_dir.map(Path::to_path_buf),
            scope_file: self.scope_file.clone(),
            ledger_file: self.ledger_file.clone(),
        })
    }

    /// Cryptanalysis: attempt to factor a small RSA modulus.
    pub fn factor_rsa(&self, e: u64, n: u64) -> Result<Value> {
        rsa_factor(e, n)
    }

    /// Cryptanalysis: frequency analysis on ciphertext bytes.
    pub fn frequency_analysis(&self, data: &[u8]) -> Result<Value> {
        frequency_analysis(data)
    }

    /// Cryptanalysis: Shannon entropy of a byte slice.
    pub fn entropy_score(&self, data: &[u8]) -> Result<Value> {
        entropy_score(data)
    }

    /// Protocol analysis on a packet capture CSV.
    pub fn analyze_protocol(&self, path: &Path) -> Result<Value> {
        analyze_protocol_capture(path)
    }
}

// ─── Prelude ─────────────────────────────────────────────────────────────────

pub mod prelude {
    pub use crate::{
        AssessmentInput, AuthorizationScope, Workbench, analyze_iq, analyze_trace,
        assess_engagement, audit_to_sarif, create_manifest, create_scope_file,
        export_html_report, export_markdown_report, export_sarif_report,
        generate_demo_workspace, inspect_firmware_binary, launch_gui, scan_source_tree,
        simulate_qubit, verify_audit_ledger, verify_manifest, verify_scope_file,
        rsa_factor, aes_ctr_reuse, frequency_analysis, entropy_score,
        vigenere_crack, xor_key_recovery,
        analyze_protocol_capture, detect_protocol_anomalies,
    };
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn workbench_builder_defaults() {
        let wb = Workbench::new();
        assert!(wb.sample_rate_hz.is_none());
        assert!((wb.physical_threshold - 6.0).abs() < f64::EPSILON);
    }

    #[test]
    fn workbench_builder_chain() {
        let wb = Workbench::new()
            .sample_rate(2e6)
            .physical_threshold(4.5);
        assert_eq!(wb.sample_rate_hz, Some(2e6));
        assert!((wb.physical_threshold - 4.5).abs() < f64::EPSILON);
    }

    #[test]
    fn rsa_factor_tiny() {
        let res = rsa_factor(65537, 3233).unwrap();
        let factors = res["factors"].as_array().unwrap();
        assert!(factors.len() >= 2);
    }

    #[test]
    fn entropy_score_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let res = entropy_score(&data).unwrap();
        let e = res["entropy_bits"].as_f64().unwrap();
        assert!(e > 7.9); // near-maximum for uniform
    }

    #[test]
    fn frequency_analysis_basic() {
        let data = b"AAABBBCCC";
        let res = frequency_analysis(data).unwrap();
        assert!(res["frequencies"].is_object());
    }

    #[test]
    fn xor_key_recovery_roundtrip() {
        let key = b"SECRET";
        let plain = b"Hello, World! This is a test message for XOR.";
        let cipher: Vec<u8> = plain.iter().enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let res = xor_key_recovery(&cipher, key.len()).unwrap();
        let recovered = res["recovered_key_hex"].as_str().unwrap();
        assert_eq!(recovered, hex::encode(key));
    }
}
