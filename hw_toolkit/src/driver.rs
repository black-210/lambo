use anyhow::{Result, Context};
use num_complex::Complex64;
use serde::{Deserialize, Serialize};

/// Metadata advertised by a capture source.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareCapabilities {
    pub device_name: String,
    pub sample_rate_hz: f64,
    pub supports_iq: bool,
    pub supports_analog_trace: bool,
    pub read_only_passive: bool,
}

/// Trait that every hardware driver must implement.
pub trait HardwareCaptureSource {
    fn capabilities(&self) -> HardwareCapabilities;
    fn read_iq_block(&mut self, max_samples: usize) -> Result<Vec<Complex64>>;
    fn read_trace_block(&mut self, max_samples: usize) -> Result<Vec<f64>>;
}

/// In‑memory mock driver – useful for demos and unit tests.
pub struct MemoryHardwareSource {
    caps: HardwareCapabilities,
    iq_buf: Vec<Complex64>,
    trace_buf: Vec<f64>,
    iq_cursor: usize,
    trace_cursor: usize,
}

impl MemoryHardwareSource {
    pub fn new(name: impl Into<String>, sample_rate_hz: f64) -> Self {
        Self {
            caps: HardwareCapabilities {
                device_name: name.into(),
                sample_rate_hz,
                supports_iq: true,
                supports_analog_trace: true,
                read_only_passive: true,
            },
            iq_buf: Vec::new(),
            trace_buf: Vec::new(),
            iq_cursor: 0,
            trace_cursor: 0,
        }
    }
    pub fn with_iq(mut self, samples: Vec<Complex64>) -> Self {
        self.iq_buf = samples;
        self
    }
    pub fn with_trace(mut self, trace: Vec<f64>) -> Self {
        self.trace_buf = trace;
        self
    }
}

impl HardwareCaptureSource for MemoryHardwareSource {
    fn capabilities(&self) -> HardwareCapabilities { self.caps.clone() }
    fn read_iq_block(&mut self, max_samples: usize) -> Result<Vec<Complex64>> {
        if self.iq_cursor >= self.iq_buf.len() { return Ok(Vec::new()) }
        let end = (self.iq_cursor + max_samples).min(self.iq_buf.len());
        let slice = self.iq_buf[self.iq_cursor..end].to_vec();
        self.iq_cursor = end;
        Ok(slice)
    }
    fn read_trace_block(&mut self, max_samples: usize) -> Result<Vec<f64>> {
        if self.trace_cursor >= self.trace_buf.len() { return Ok(Vec::new()) }
        let end = (self.trace_cursor + max_samples).min(self.trace_buf.len());
        let slice = self.trace_buf[self.trace_cursor..end].to_vec();
        self.trace_cursor = end;
        Ok(slice)
    }
}
