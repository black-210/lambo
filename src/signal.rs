use anyhow::{Context, Result, bail};
use ndarray::ArrayD;
use ndarray_npy::read_npy;
use num_complex::{Complex32, Complex64};
use rustfft::FftPlanner;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SAMPLES: usize = 2_000_000;

fn sha256_file(path: &Path) -> Result<String> {
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

fn parse_csv(path: &Path) -> Result<Vec<Complex64>> {
    let file = File::open(path).with_context(|| format!("Opening {}", path.display()))?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .comment(Some(b'#'))
        .from_reader(file);
    let mut samples = Vec::new();
    let mut skipped_header = false;

    for (index, record) in reader.records().enumerate() {
        let record = record.with_context(|| format!("Reading CSV row {}", index + 1))?;
        if record.is_empty() {
            continue;
        }
        if record.len() != 2 {
            bail!(
                "CSV row {} must contain exactly two I,Q columns.",
                index + 1
            );
        }
        let parsed = record[0].trim().parse::<f64>().and_then(|i| {
            record[1]
                .trim()
                .parse::<f64>()
                .map(|q| Complex64::new(i, q))
        });
        match parsed {
            Ok(sample) => samples.push(sample),
            Err(_) if samples.is_empty() && !skipped_header => skipped_header = true,
            Err(_) => bail!("CSV row {} contains a non-numeric I,Q value.", index + 1),
        }
        if samples.len() > MAX_SAMPLES {
            bail!("Input exceeds the {MAX_SAMPLES} sample limit.");
        }
    }
    Ok(samples)
}

fn real_array_to_iq(data: ArrayD<f64>) -> Result<Vec<Complex64>> {
    let shape = data.shape();
    match shape {
        [_] => Ok(data
            .iter()
            .map(|value| Complex64::new(*value, 0.0))
            .collect()),
        [_, 2] => {
            let (pairs, _) = data
                .as_slice()
                .context("NPY array is not contiguous.")?
                .as_chunks::<2>();
            Ok(pairs
                .iter()
                .map(|pair| Complex64::new(pair[0], pair[1]))
                .collect())
        }
        _ => bail!("NPY must be a 1D complex array or a 2D real array with I,Q columns."),
    }
}

fn complex_array_to_iq(data: ArrayD<Complex64>) -> Result<Vec<Complex64>> {
    match data.shape() {
        [_] => Ok(data.iter().copied().collect()),
        _ => bail!("Complex NPY input must be a one-dimensional array."),
    }
}

fn parse_npy(path: &Path) -> Result<Vec<Complex64>> {
    if let Ok(data) = read_npy::<_, ArrayD<Complex64>>(path) {
        return complex_array_to_iq(data);
    }
    if let Ok(data) = read_npy::<_, ArrayD<Complex32>>(path) {
        let converted = data.mapv(|sample| Complex64::new(sample.re as f64, sample.im as f64));
        return complex_array_to_iq(converted);
    }
    if let Ok(data) = read_npy::<_, ArrayD<f64>>(path) {
        return real_array_to_iq(data);
    }
    if let Ok(data) = read_npy::<_, ArrayD<f32>>(path) {
        return real_array_to_iq(data.mapv(f64::from));
    }
    if let Ok(data) = read_npy::<_, ArrayD<i64>>(path) {
        return real_array_to_iq(data.mapv(|value| value as f64));
    }
    if let Ok(data) = read_npy::<_, ArrayD<i32>>(path) {
        return real_array_to_iq(data.mapv(f64::from));
    }
    bail!("Could not read supported NPY data; use numeric 1D complex or 2D real I,Q arrays.")
}

fn load_iq(path: &Path) -> Result<Vec<Complex64>> {
    let metadata = path
        .metadata()
        .with_context(|| format!("Reading input metadata for {}", path.display()))?;
    if !metadata.is_file() {
        bail!("IQ input is not a file: {}", path.display());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        bail!("Input exceeds the 256 MiB size limit.");
    }

    let samples = match path.extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("csv") => parse_csv(path)?,
        Some(extension) if extension.eq_ignore_ascii_case("npy") => parse_npy(path)?,
        _ => bail!("Supported IQ formats are .csv and .npy."),
    };
    if samples.len() < 2 {
        bail!("IQ input must contain at least two samples.");
    }
    if samples.len() > MAX_SAMPLES {
        bail!("Input exceeds the {MAX_SAMPLES} sample limit.");
    }
    if samples.iter().any(|sample| {
        !sample.re.is_finite() || !sample.im.is_finite() || !sample.norm().is_finite()
    }) {
        bail!("IQ input contains non-finite values or magnitudes outside the supported range.");
    }
    Ok(samples)
}

fn analyze_samples(samples: &[Complex64], sample_rate: Option<f64>) -> Result<Value> {
    if samples.len() < 2 {
        bail!("IQ input must contain at least two samples.");
    }
    if sample_rate.is_some_and(|rate| !rate.is_finite() || rate <= 0.0) {
        bail!("Sample rate must be a finite positive number.");
    }

    let scale = samples
        .iter()
        .map(|sample| sample.norm())
        .fold(0.0, f64::max);
    let normalized: Vec<Complex64> = if scale > 0.0 {
        samples.iter().map(|sample| *sample / scale).collect()
    } else {
        samples.to_vec()
    };
    let count = normalized.len() as f64;
    let mean = normalized
        .iter()
        .copied()
        .fold(Complex64::new(0.0, 0.0), |sum, value| sum + value)
        / count;
    let rms_normalized =
        (normalized.iter().map(|value| value.norm_sqr()).sum::<f64>() / count).sqrt();
    let peak_normalized = normalized
        .iter()
        .map(|value| value.norm())
        .fold(0.0, f64::max);
    let mean_i = mean.re * scale;
    let mean_q = mean.im * scale;
    let rms = rms_normalized * scale;
    let peak = peak_normalized * scale;

    let mut spectrum: Vec<Complex64> = normalized.iter().map(|value| *value - mean).collect();
    let mut planner = FftPlanner::<f64>::new();
    planner
        .plan_fft_forward(spectrum.len())
        .process(&mut spectrum);
    let len = spectrum.len();
    let shift = len.div_ceil(2);
    let mut power = Vec::with_capacity(len);
    let mut frequencies = Vec::with_capacity(len);
    for index in 0..len {
        let original_index = (index + shift) % len;
        power.push(spectrum[original_index].norm_sqr());
        let signed_bin = if original_index < len.div_ceil(2) {
            original_index as isize
        } else {
            original_index as isize - len as isize
        };
        let frequency = if let Some(rate) = sample_rate {
            signed_bin as f64 * rate / len as f64
        } else {
            signed_bin as f64 / len as f64
        };
        frequencies.push(frequency);
    }

    let total_power: f64 = power.iter().sum();
    let mut peak_indices: Vec<usize> = (0..len)
        .filter(|index| {
            total_power > 0.0
                && power[*index] >= power[(*index + len - 1) % len]
                && power[*index] > power[(*index + 1) % len]
        })
        .collect();
    peak_indices.sort_by(|left, right| power[*right].total_cmp(&power[*left]));
    peak_indices.truncate(5);

    let entropy = if total_power > 0.0 {
        -power
            .iter()
            .filter(|value| **value > 0.0)
            .map(|value| {
                let probability = value / total_power;
                probability * probability.log2()
            })
            .sum::<f64>()
    } else {
        0.0
    };
    let unit = if sample_rate.is_some() {
        "Hz"
    } else {
        "cycles/sample"
    };
    let spectral_peaks: Vec<Value> = peak_indices
        .iter()
        .map(|index| {
            json!({
                "frequency": frequencies[*index],
                "unit": unit,
                "relative_power": power[*index] / total_power
            })
        })
        .collect();
    let observations = if let Some(strongest) = spectral_peaks.first() {
        vec![format!(
            "Strongest spectral component: {:.6} {}, {:.4}% of measured spectral power.",
            strongest["frequency"].as_f64().unwrap_or_default(),
            unit,
            strongest["relative_power"].as_f64().unwrap_or_default() * 100.0
        )]
    } else {
        vec!["No non-zero spectral component was measured after mean removal.".to_owned()]
    };

    Ok(json!({
        "schema_version": 1,
        "analysis": "offline_iq_spectral_baseline",
        "input": {
            "sample_count": samples.len(),
            "sample_rate_hz": sample_rate
        },
        "metrics": {
            "mean_i": mean_i,
            "mean_q": mean_q,
            "dc_offset_magnitude": mean_i.hypot(mean_q),
            "rms_magnitude": rms,
            "peak_magnitude": peak,
            "crest_factor": if rms > 0.0 { peak / rms } else { 0.0 },
            "spectral_entropy_bits": entropy
        },
        "spectral_peaks": spectral_peaks,
        "observations": observations,
        "limitations": [
            "These are signal measurements, not vulnerability findings.",
            "No reference capture or calibrated instrument metadata was supplied.",
            "IQ samples alone cannot establish a quantum-mechanical property or security impact."
        ]
    }))
}

pub fn analyze_iq(path: &Path, sample_rate: Option<f64>) -> Result<Value> {
    let samples = load_iq(path)?;
    let mut report = analyze_samples(&samples, sample_rate)?;
    report["input"]["name"] = json!(path.file_name().unwrap_or_default().to_string_lossy());
    report["input"]["sha256"] = json!(sha256_file(path)?);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::f64::consts::PI;

    #[test]
    fn recovers_known_tone_frequency() {
        let count = 128;
        let samples: Vec<Complex64> = (0..count)
            .map(|index| {
                let angle = 2.0 * PI * 8.0 * index as f64 / count as f64;
                Complex64::new(angle.cos(), angle.sin())
            })
            .collect();
        let report = analyze_samples(&samples, Some(128.0)).unwrap();
        assert_eq!(report["spectral_peaks"][0]["frequency"], 8.0);
        assert!((report["metrics"]["rms_magnitude"].as_f64().unwrap() - 1.0).abs() < 1e-12);
    }

    #[test]
    fn rejects_invalid_sample_rate() {
        let samples = vec![Complex64::new(1.0, 0.0); 4];
        assert!(analyze_samples(&samples, Some(0.0)).is_err());
    }
}
