use anyhow::{Context, Result, bail};
use csv::ReaderBuilder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_TRACE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRACE_SAMPLES: usize = 2_000_000;

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
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

fn load_trace(path: &Path) -> Result<Vec<f64>> {
    let file =
        File::open(path).with_context(|| format!("Opening measurement file {}", path.display()))?;
    if file.metadata()?.len() > MAX_TRACE_BYTES {
        bail!("Measurement file exceeds the 256 MiB size limit.");
    }
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .comment(Some(b'#'))
        .from_reader(file);
    let mut values = Vec::new();
    let mut skipped_header = false;
    for (index, record) in reader.records().enumerate() {
        let record = record.with_context(|| format!("Reading measurement row {}", index + 1))?;
        if record.is_empty() {
            continue;
        }
        if !(1..=2).contains(&record.len()) {
            bail!(
                "Trace CSV row {} must contain one measurement or time,measurement.",
                index + 1
            );
        }
        let parsed = record[record.len() - 1].trim().parse::<f64>();
        match parsed {
            Ok(value) => values.push(value),
            Err(_) if values.is_empty() && !skipped_header => skipped_header = true,
            Err(_) => bail!("Non-numeric measurement at CSV row {}.", index + 1),
        }
        if values.len() > MAX_TRACE_SAMPLES {
            bail!("Trace exceeds the {MAX_TRACE_SAMPLES} sample limit.");
        }
    }
    if values.len() < 3 {
        bail!("Measurement trace must contain at least three numeric samples.");
    }
    if values.iter().any(|value| !value.is_finite()) {
        bail!("Measurement trace contains NaN or infinite values.");
    }
    let supported_max = f64::MAX.sqrt() / 2.0;
    if values.iter().any(|value| value.abs() > supported_max) {
        bail!("Measurement values exceed the supported numeric range.");
    }
    Ok(values)
}

fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let middle = sorted.len() / 2;
    if sorted.len().is_multiple_of(2) {
        (sorted[middle - 1] + sorted[middle]) / 2.0
    } else {
        sorted[middle]
    }
}

fn rms(values: &[f64]) -> f64 {
    let scale = values.iter().map(|value| value.abs()).fold(0.0, f64::max);
    if scale == 0.0 {
        return 0.0;
    }
    let normalized_square_sum = values
        .iter()
        .map(|value| (value / scale).powi(2))
        .sum::<f64>();
    scale * (normalized_square_sum / values.len() as f64).sqrt()
}

fn peak_to_peak(values: &[f64]) -> f64 {
    let min = values.iter().copied().fold(f64::INFINITY, f64::min);
    let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    max - min
}

pub fn analyze_trace(path: &Path, reference_path: Option<&Path>, threshold: f64) -> Result<Value> {
    if !threshold.is_finite() || threshold <= 0.0 {
        bail!("Outlier threshold must be a finite positive number.");
    }
    let values = load_trace(path)?;
    let center = median(&values);
    let deviations: Vec<f64> = values.iter().map(|value| (value - center).abs()).collect();
    let mad = median(&deviations);
    let robust_sigma = 1.4826 * mad;
    let outliers = deviations
        .iter()
        .filter(|deviation| {
            if robust_sigma > 0.0 {
                **deviation > threshold * robust_sigma
            } else {
                **deviation > 0.0
            }
        })
        .count();
    let trace_rms = rms(&values);
    let mut report = json!({
        "schema_version": 1,
        "analysis": "offline_physical_measurement_trace",
        "input": {
            "name": path.file_name().unwrap_or_default().to_string_lossy(),
            "sample_count": values.len(),
            "sha256": sha256_file(path)?
        },
        "metrics": {
            "mean": values.iter().sum::<f64>() / values.len() as f64,
            "median": center,
            "rms": trace_rms,
            "peak_absolute": values.iter().map(|value| value.abs()).fold(0.0, f64::max),
            "peak_to_peak": peak_to_peak(&values),
            "median_absolute_deviation": mad,
            "robust_outlier_threshold": threshold,
            "robust_outlier_count": outliers,
            "robust_outlier_fraction": outliers as f64 / values.len() as f64
        },
        "observations": [format!(
            "Found {outliers} robust statistical outlier(s) using a {threshold:.2} scaled-MAD threshold."
        )],
        "limitations": [
            "This is a generic measurement-trace screen, not a physical vulnerability test.",
            "Outliers may be valid events, sensor artifacts, or collection errors.",
            "No key extraction, device interaction, or exploit testing is performed."
        ]
    });

    if let Some(reference_path) = reference_path {
        let reference = load_trace(reference_path)?;
        let reference_rms = rms(&reference);
        let ratio = if reference_rms > 0.0 {
            let value = trace_rms / reference_rms;
            if value.is_finite() {
                json!(value)
            } else {
                Value::Null
            }
        } else {
            Value::Null
        };
        report["reference"] = json!({
            "name": reference_path.file_name().unwrap_or_default().to_string_lossy(),
            "sample_count": reference.len(),
            "sha256": sha256_file(reference_path)?
        });
        report["comparison"] = json!({
            "median_delta": center - median(&reference),
            "rms_delta": trace_rms - reference_rms,
            "rms_ratio": ratio,
            "peak_to_peak_delta": peak_to_peak(&values) - peak_to_peak(&reference)
        });
        report["limitations"]
            .as_array_mut()
            .context("Internal report format error.")?
            .push(json!(
                "Reference comparison uses aggregate statistics and does not establish causation."
            ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_single_outlier_in_constant_trace() {
        let path =
            std::env::temp_dir().join(format!("iq-workbench-trace-{}.csv", std::process::id()));
        fs::write(&path, "0\n0\n0\n0\n0\n0\n0\n0\n0\n100\n").unwrap();
        let report = analyze_trace(&path, None, 6.0).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report["metrics"]["robust_outlier_count"], 1);
    }
}
