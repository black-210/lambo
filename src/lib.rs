//! # IQ Research & Hardware Red-Team Workbench
//!
//! Comprehensive, offline-first, authorized security assessment & research suite usable both as
//! a **CLI/Web-GUI platform** and as an ergonomic **Rust library**:
//!
//! - **RF / IQ Signal DSP (`signal`)**: `.csv`, `.npy`, `.cf32`, `.cs16`, `.cs8`, `.cu8`, `.wav`,
//!   `.sigmf-meta` + Hann FFT, Welch PSD, CA-CFAR spurs, IRR, Higher-Order Cumulants AMC, and
//!   cyclostationary symbol-rate estimation.
//! - **Physical Side-Channel Screening (`physical`)**: MAD/CUSUM glitch detection, clock-harmonic
//!   comb, Welch's t-test TVLA (single trace & multi-trace matrix), NICV, SNR(t), and xcorr alignment.
//! - **Hardware Discovery & Bus Decoders (`hardware`)**: Passive COM/USB inventory, `.vcd` logic
//!   analyzer parser, UART/SPI/I2C decoders, and `HardwareCaptureSource` live streaming trait.
//! - **From-Scratch Cryptanalysis & Randomness Suite (`cryptanalysis`, `bigint`)**: Arbitrary-precision
//!   RSA audits (Fermat, Pollard p-1, Pollard-Rho Brent, Wiener continued fractions, Batch GCD,
//!   Common Modulus), real LLL lattice basis reduction & subset-sum audit, Berlekamp-Massey GF(2),
//!   NIST SP 800-22 suite, ECB/CTR/Crib-Drag/Vigenère/XOR.
//! - **Protocol & Firmware Inspection (`protocol`, `firmware`, `audit`)**: Native binary `.pcap`
//!   & `.csv` anomaly engine, ELF hardening (`PIE/NX/RELRO/Canary`), ARM Cortex-M vector check,
//!   YARA-lite rules, SARIF v2.1.0 hardware/code scanner.
//! - **Autonomous Physical AI & Governance (`ai`, `assess`, `evidence`, `legal`)**: Cross-domain
//!   offline correlation engine, bilingual Arabic/English diagnostic interpreter, optional external
//!   LLM chat, authorization scope verification, and SHA-256 hash-chained audit ledger.
//!
//! ## Quick Library Usage
//! ```no_run
//! use iq_research_workbench::prelude::*;
//! use std::path::Path;
//!
//! let wb = Workbench::new().sample_rate(2_000_000.0);
//! let iq = wb.analyze_iq_file(Path::new("capture.csv"))?;
//! # Ok::<(), anyhow::Error>(())
//! ```

pub mod ai;
pub mod assess;
pub mod audit;
pub mod bigint;
pub mod common;
pub mod cryptanalysis;
pub mod evidence;
pub mod firmware;
pub mod gui;
pub mod hardware;
pub mod legal;
pub mod physical;
pub mod protocol;
pub mod quantum;
pub mod signal;

pub use ai::{assess_and_diagnose, autonomous_workspace_audit, diagnose_report_offline};
pub use assess::{
    AssessmentInput, assess_engagement, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace,
};
pub use audit::{audit_to_sarif, scan_for_issues, scan_source_tree};
pub use bigint::{BigInt, BigUint, extended_gcd, mod_inverse};
pub use cryptanalysis::{
    aes_ctr_reuse, berlekamp_massey_gf2, coppersmith_stub, crib_drag, detect_ecb_blocks,
    entropy_score, frequency_analysis, lll_reduce, lll_subset_sum_audit, nist_randomness_suite,
    rsa_audit, rsa_batch_gcd, rsa_common_modulus_check, rsa_factor, vigenere_crack,
    xor_key_recovery,
};
pub use evidence::{create_manifest, verify_manifest};
pub use firmware::inspect_firmware_binary;
pub use gui::launch_gui;
pub use hardware::{
    HardwareCapabilities, HardwareCaptureSource, MemoryHardwareSource, decode_i2c_vcd,
    decode_spi_vcd, decode_uart_vcd, discover_local_hardware, parse_vcd_file,
};
pub use legal::{
    AuditLedgerEntry, AuthorizationScope, append_audit_entry, create_scope_file,
    verify_audit_ledger, verify_scope_file,
};
pub use physical::{analyze_trace, analyze_trace_matrix};
pub use protocol::{Packet, analyze_protocol_capture, detect_anomalies as detect_protocol_anomalies};
pub use quantum::{simulate_bb84, simulate_circuit, simulate_qubit};
pub use signal::{analyze_iq, analyze_samples};

use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Ergonomic high-level façade for embedding the entire workbench as a Rust library.
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

    pub fn analyze_hardware_iq(&self, source: &mut dyn HardwareCaptureSource, max_samples: usize) -> Result<Value> {
        let caps = source.capabilities();
        let samples = source.read_iq_block(max_samples)?;
        analyze_samples(&samples, Some(caps.sample_rate_hz))
    }

    pub fn analyze_physical_trace(
        &self,
        trace: &Path,
        reference: Option<&Path>,
    ) -> Result<Value> {
        analyze_trace(trace, reference, self.physical_threshold)
    }

    pub fn analyze_side_channel_matrix(&self, matrix_csv: &Path, align_window: usize) -> Result<Value> {
        analyze_trace_matrix(matrix_csv, align_window)
    }

    pub fn audit_hardware_source(&self, root: &Path) -> Result<Value> {
        scan_source_tree(root)
    }

    pub fn inspect_firmware(&self, firmware_path: &Path) -> Result<Value> {
        inspect_firmware_binary(firmware_path)
    }

    pub fn discover_hardware(&self) -> Result<Value> {
        discover_local_hardware()
    }

    pub fn decode_uart(&self, vcd_path: &Path, channel: Option<&str>, baud_hz: Option<f64>) -> Result<Value> {
        decode_uart_vcd(vcd_path, channel, baud_hz)
    }

    pub fn decode_i2c(&self, vcd_path: &Path, scl: Option<&str>, sda: Option<&str>) -> Result<Value> {
        decode_i2c_vcd(vcd_path, scl, sda)
    }

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

    pub fn ai_autonomous_audit(&self, workspace_dir: &Path) -> Result<Value> {
        autonomous_workspace_audit(
            workspace_dir,
            self.scope_file.as_deref(),
            self.ledger_file.as_deref(),
            self.sample_rate_hz,
        )
    }

    pub fn ai_diagnose(&self, report: &Value, question: Option<&str>, lang: &str) -> Value {
        diagnose_report_offline(report, question, lang)
    }

    pub fn audit_rsa(&self, e_str: &str, n_str: &str, max_steps: usize) -> Result<Value> {
        rsa_audit(e_str, n_str, max_steps)
    }

    pub fn factor_rsa(&self, e: u64, n: u64) -> Result<Value> {
        rsa_factor(e, n)
    }

    pub fn nist_randomness(&self, data: &[u8]) -> Result<Value> {
        nist_randomness_suite(data)
    }

    pub fn lfsr_linear_complexity(&self, data: &[u8]) -> Result<Value> {
        berlekamp_massey_gf2(data)
    }

    pub fn lll_lattice_reduce(&self, basis: &[Vec<f64>], delta: f64) -> Result<Value> {
        lll_reduce(basis, delta)
    }

    pub fn frequency_analysis(&self, data: &[u8]) -> Result<Value> {
        frequency_analysis(data)
    }

    pub fn entropy_score(&self, data: &[u8]) -> Result<Value> {
        entropy_score(data)
    }

    pub fn analyze_protocol(&self, path: &Path) -> Result<Value> {
        analyze_protocol_capture(path)
    }
}

pub mod prelude {
    pub use crate::{
        AssessmentInput, AuthorizationScope, BigInt, BigUint, HardwareCapabilities,
        HardwareCaptureSource, MemoryHardwareSource, Packet, Workbench, aes_ctr_reuse, analyze_iq,
        analyze_protocol_capture, analyze_samples, analyze_trace, analyze_trace_matrix,
        assess_and_diagnose, assess_engagement, audit_to_sarif, autonomous_workspace_audit,
        berlekamp_massey_gf2, create_manifest, create_scope_file, crib_drag, decode_i2c_vcd,
        decode_spi_vcd, decode_uart_vcd, detect_ecb_blocks, detect_protocol_anomalies,
        diagnose_report_offline, discover_local_hardware, entropy_score, export_html_report,
        export_markdown_report, export_sarif_report, extended_gcd, frequency_analysis,
        generate_demo_workspace, inspect_firmware_binary, launch_gui, lll_reduce,
        lll_subset_sum_audit, mod_inverse, nist_randomness_suite, parse_vcd_file, rsa_audit,
        rsa_batch_gcd, rsa_common_modulus_check, rsa_factor, scan_source_tree, simulate_bb84,
        simulate_circuit, simulate_qubit, verify_audit_ledger, verify_manifest, verify_scope_file,
        vigenere_crack, xor_key_recovery,
    };
}

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn workbench_builder_and_library_methods_work() {
        let wb = Workbench::new().sample_rate(2e6).physical_threshold(4.5);
        assert_eq!(wb.sample_rate_hz, Some(2e6));
        assert!((wb.physical_threshold - 4.5).abs() < f64::EPSILON);

        let rsa = wb.audit_rsa("17", "3233", 5000).unwrap();
        assert_eq!(rsa["vulnerable"], true);
    }

    #[test]
    fn xor_key_recovery_roundtrip() {
        let key = b"SECRET";
        let plain = b"Hello, World! This is an authorized hardware security research test message containing plenty of standard English letters for statistical scoring.";
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect();
        let res = xor_key_recovery(&cipher, key.len()).unwrap();
        assert_eq!(res["recovered_key_hex"], hex::encode(key));
    }
}
