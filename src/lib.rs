//! # IQ Research Workbench
//!
//! An offline-first, authorized hardware security assessment, IQ signal screening,
//! physical trace screening, evidence integrity, and educational quantum library.
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
pub mod evidence;
pub mod firmware;
pub mod gui;
pub mod legal;
pub mod physical;
pub mod quantum;
pub mod signal;

pub use assess::{
    AssessmentInput, assess_engagement, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace,
};
pub use audit::{audit_to_sarif, scan_for_issues, scan_source_tree};
pub use evidence::{create_manifest, verify_manifest};
pub use firmware::inspect_firmware_binary;
pub use gui::launch_gui;
pub use legal::{
    AuditLedgerEntry, AuthorizationScope, append_audit_entry, create_scope_file,
    verify_audit_ledger, verify_scope_file,
};
pub use physical::analyze_trace;
pub use quantum::simulate_qubit;
pub use signal::{analyze_iq, analyze_samples};

use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Ergonomic high-level facade for using the workbench as a Rust library.
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
}

pub mod prelude {
    pub use crate::{
        AssessmentInput, AuthorizationScope, Workbench, analyze_iq, analyze_trace,
        assess_engagement, audit_to_sarif, create_manifest, create_scope_file,
        export_html_report, export_markdown_report, export_sarif_report, generate_demo_workspace,
        inspect_firmware_binary, launch_gui, scan_source_tree, simulate_qubit, verify_audit_ledger,
        verify_manifest, verify_scope_file,
    };
}
