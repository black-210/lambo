use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("Opening {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

pub fn spectral_flatness(power_bins: &[f64]) -> f64 {
    if power_bins.is_empty() {
        return 0.0;
    }
    let total: f64 = power_bins.iter().sum();
    if total <= 1e-18 {
        return 0.0;
    }
    let positive: Vec<f64> = power_bins.iter().copied().filter(|p| *p > 1e-18).collect();
    if positive.is_empty() {
        return 0.0;
    }
    let log_mean = positive.iter().map(|p| p.ln()).sum::<f64>() / positive.len() as f64;
    let arith_mean = total / power_bins.len() as f64;
    if arith_mean > 0.0 {
        (log_mean.exp() / arith_mean).clamp(0.0, 1.0)
    } else {
        0.0
    }
     
}