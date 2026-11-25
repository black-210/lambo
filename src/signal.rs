use crate::common::{median, sha256_file, spectral_flatness};
use anyhow::{Context, Result, bail};
use ndarray::ArrayD;
use ndarray_npy::read_npy;
use num_complex::{Complex32, Complex64};
use rustfft::FftPlanner;
use serde_json::{Value, json};
use std::f64::consts::PI;
use std::fs::File;
use std::path::Path;

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SAMPLES: usize = 2_000_000;

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

fn parse_raw_cf32(path: &Path) -> Result<Vec<Complex64>> {
    let bytes = std::fs::read(path).with_context(|| format!("Reading {}", path.display()))?;
    let (chunks, remainder) = bytes.as_chunks::<8>();
    if !remainder.is_empty() {
        bail!("Raw cf32 IQ file length must be a multiple of 8 bytes (I,Q float32 pairs).");
    }
    Ok(chunks
        .iter()
        .take(MAX_SAMPLES)
        .map(|chunk| {
            let i = f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as f64;
            let q = f32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) as f64;
            Complex64::new(i, q)
        })
        .collect())
}

fn parse_raw_cs8(path: &Path) -> Result<Vec<Complex64>> {
    let bytes = std::fs::read(path).with_context(|| format!("Reading {}", path.display()))?;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        bail!("Raw cs8 IQ file length must be a multiple of 2 bytes (I,Q int8 pairs).");
    }
    Ok(pairs
        .iter()
        .take(MAX_SAMPLES)
        .map(|pair| Complex64::new((pair[0] as i8) as f64 / 128.0, (pair[1] as i8) as f64 / 128.0))
        .collect())
}

fn parse_raw_cu8(path: &Path) -> Result<Vec<Complex64>> {
    let bytes = std::fs::read(path).with_context(|| format!("Reading {}", path.display()))?;
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        bail!("Raw cu8 IQ file length must be a multiple of 2 bytes (I,Q uint8 pairs).");
    }
    Ok(pairs
        .iter()
        .take(MAX_SAMPLES)
        .map(|pair| {
            Complex64::new(
                (pair[0] as f64 - 127.5) / 127.5,
                (pair[1] as f64 - 127.5) / 127.5,
            )
        })
        .collect())
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

    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let samples = match ext.as_str() {
        "csv" => parse_csv(path)?,
        "npy" => parse_npy(path)?,
        "cf32" | "fc32" => parse_raw_cf32(path)?,
        "cs8" | "sc8" => parse_raw_cs8(path)?,
        "cu8" | "uc8" => parse_raw_cu8(path)?,
        _ => bail!("Supported IQ formats are .csv, .npy, .cf32, .cs8, and .cu8."),
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

fn compute_iq_impairments(normalized: &[Complex64], mean: Complex64) -> (f64, f64, f64, f64) {
    let count = normalized.len() as f64;
    let mut sum_i2 = 0.0;
    let mut sum_q2 = 0.0;
    let mut sum_iq = 0.0;
    for s in normalized {
        let i = s.re - mean.re;
        let q = s.im - mean.im;
        sum_i2 += i * i;
        sum_q2 += q * q;
        sum_iq += i * q;
    }
    let i_rms_norm = (sum_i2 / count).sqrt();
    let q_rms_norm = (sum_q2 / count).sqrt();
    let gain_imbalance_db = if i_rms_norm > 1e-12 && q_rms_norm > 1e-12 {
        20.0 * (i_rms_norm / q_rms_norm).log10()
    } else {
        0.0
    };
    let denom = (sum_i2 * sum_q2).sqrt();
    let phase_skew_deg = if denom > 1e-12 {
        let rho = (sum_iq / denom).clamp(-1.0, 1.0);
        rho.asin().to_degrees()
    } else {
        0.0
    };
    (i_rms_norm, q_rms_norm, gain_imbalance_db, phase_skew_deg)
}

fn envelope_and_phase_profile(normalized: &[Complex64]) -> (f64, f64, &'static str) {
    let mags: Vec<f64> = normalized.iter().map(|s| s.norm()).collect();
    let mean_m = mags.iter().sum::<f64>() / mags.len() as f64;
    let var_m = mags.iter().map(|m| (m - mean_m).powi(2)).sum::<f64>() / mags.len() as f64;
    let std_m = var_m.sqrt();
    let env_kurtosis = if std_m > 1e-12 {
        mags.iter().map(|m| ((m - mean_m) / std_m).powi(4)).sum::<f64>() / mags.len() as f64 - 3.0
    } else {
        0.0
    };

    let mut dphi_sq = 0.0;
    let mut dphi_count = 0_usize;
    for pair in normalized.windows(2) {
        if pair[0].norm_sqr() > 1e-12 && pair[1].norm_sqr() > 1e-12 {
            let prod = pair[1] * pair[0].conj();
            let dphi = prod.arg();
            dphi_sq += dphi * dphi;
            dphi_count += 1;
        }
    }
    let phase_diff_rms = if dphi_count > 0 {
        (dphi_sq / dphi_count as f64).sqrt()
    } else {
        0.0
    };
    let cv = if mean_m > 1e-12 { std_m / mean_m } else { 0.0 };
    let character = if cv < 0.12 && phase_diff_rms < 0.25 {
        "narrowband-cw-or-unmodulated-carrier"
    } else if cv < 0.25 {
        "constant-envelope-fm-pm-or-fsk"
    } else if env_kurtosis > 2.0 {
        "pulsed-or-bursty-transmission"
    } else {
        "multilevel-qam-ofdm-or-noise-like"
    };
    (env_kurtosis, phase_diff_rms, character)
}

fn detect_bursts(normalized: &[Complex64]) -> (usize, Vec<Value>) {
    let n = normalized.len();
    if n < 16 {
        return (0, Vec::new());
    }
    let win = (n / 64).clamp(4, 1024);
    let mut window_rms = Vec::new();
    let mut idx = 0;
    while idx < n {
        let end = (idx + win).min(n);
        let slice = &normalized[idx..end];
        let e = (slice.iter().map(|s| s.norm_sqr()).sum::<f64>() / slice.len() as f64).sqrt();
        window_rms.push((idx, end, e));
        idx = end;
    }
    let energies: Vec<f64> = window_rms.iter().map(|w| w.2).collect();
    let baseline = median(&energies);
    let threshold = if baseline > 1e-9 { baseline * 2.5 } else { 1e-6 };

    let mut bursts = Vec::new();
    let mut active: Option<(usize, usize, f64)> = None;
    for (start, end, e) in window_rms {
        if e > threshold {
            active = match active {
                Some((s, _, peak)) => Some((s, end, peak.max(e))),
                None => Some((start, end, e)),
            };
        } else if let Some((s, prev_end, peak)) = active.take() {
            let ratio = if baseline > 1e-9 { peak / baseline } else { 0.0 };
            bursts.push(json!({
                "start_sample": s,
                "end_sample": prev_end,
                "peak_to_baseline_ratio": ratio
            }));
        }
    }
    if let Some((s, prev_end, peak)) = active {
        let ratio = if baseline > 1e-9 { peak / baseline } else { 0.0 };
        bursts.push(json!({
            "start_sample": s,
            "end_sample": prev_end,
            "peak_to_baseline_ratio": ratio
        }));
    }
    let total = bursts.len();
    bursts.truncate(16);
    (total, bursts)
}

fn compute_spectrogram(normalized: &[Complex64], mean: Complex64) -> Vec<Vec<f64>> {
    let n = normalized.len();
    let slices = 16_usize.min(n / 8);
    if slices == 0 {
        return Vec::new();
    }
    let slice_len = (n / slices).max(8);
    let bins = 32_usize;
    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(slice_len);
    let mut matrix = Vec::with_capacity(slices);
    let mut global_max = 1e-24_f64;

    let mut raw_slices = Vec::with_capacity(slices);
    for s in 0..slices {
        let start = s * slice_len;
        let mut buf: Vec<Complex64> = normalized[start..start + slice_len]
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let w = 0.5 * (1.0 - (2.0 * PI * i as f64 / (slice_len - 1) as f64).cos());
                (*v - mean) * w
            })
            .collect();
        fft.process(&mut buf);
        let shift = slice_len.div_ceil(2);
        let shifted: Vec<f64> = (0..slice_len)
            .map(|i| buf[(i + shift) % slice_len].norm_sqr())
            .collect();
        let mut row = Vec::with_capacity(bins);
        for b in 0..bins {
            let b_start = b * slice_len / bins;
            let b_end = ((b + 1) * slice_len / bins).max(b_start + 1).min(slice_len);
            let p = shifted[b_start..b_end]
                .iter()
                .copied()
                .fold(0.0_f64, f64::max);
            global_max = global_max.max(p);
            row.push(p);
        }
        raw_slices.push(row);
    }

    for row in raw_slices {
        let db_row = row
            .into_iter()
            .map(|p| 10.0 * (p / global_max).max(1e-10).log10())
            .collect();
        matrix.push(db_row);
    }
    matrix
}

fn occupied_bandwidth(power: &[f64], frequencies: &[f64]) -> Option<f64> {
    let total: f64 = power.iter().sum();
    if total <= 1e-18 || frequencies.len() < 2 {
        return None;
    }
    let mut cum = 0.0;
    let mut low_idx = 0;
    let mut high_idx = power.len() - 1;
    let low_thresh = 0.005 * total;
    let high_thresh = 0.995 * total;
    for (i, &p) in power.iter().enumerate() {
        cum += p;
        if cum <= low_thresh {
            low_idx = i;
        }
        if cum >= high_thresh {
            high_idx = i;
            break;
        }
    }
    Some((frequencies[high_idx] - frequencies[low_idx]).abs())
}

fn downsample_preview(
    samples: &[Complex64],
    frequencies: &[f64],
    power: &[f64],
    spectrogram: Vec<Vec<f64>>,
) -> Value {
    let iq_step = (samples.len() / 400).max(1);
    let iq_points: Vec<[f64; 2]> = samples
        .iter()
        .step_by(iq_step)
        .take(400)
        .map(|s| [s.re, s.im])
        .collect();

    let env_step = (samples.len() / 256).max(1);
    let envelope_bins: Vec<[f64; 2]> = samples
        .iter()
        .enumerate()
        .step_by(env_step)
        .take(256)
        .map(|(i, s)| [i as f64, s.norm()])
        .collect();

    let max_p = power.iter().copied().fold(0.0_f64, f64::max).max(1e-24);
    let spec_step = (power.len() / 256).max(1);
    let spectrum_bins: Vec<[f64; 2]> = power
        .iter()
        .zip(frequencies.iter())
        .step_by(spec_step)
        .take(256)
        .map(|(p, f)| {
            let db = 10.0 * (p / max_p).max(1e-12).log10();
            [*f, db]
        })
        .collect();

    json!({
        "iq_points": iq_points,
        "spectrum_bins": spectrum_bins,
        "envelope_bins": envelope_bins,
        "spectrogram": spectrogram
    })
}

pub fn analyze_samples(samples: &[Complex64], sample_rate: Option<f64>) -> Result<Value> {
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
    let dc_offset_magnitude = mean_i.hypot(mean_q);
    let rms = rms_normalized * scale;
    let peak = peak_normalized * scale;
    let dc_offset_ratio = if rms > 0.0 { dc_offset_magnitude / rms } else { 0.0 };

    let (i_rms_norm, q_rms_norm, iq_gain_imbalance_db, iq_phase_skew_deg) =
        compute_iq_impairments(&normalized, mean);
    let (envelope_kurtosis, phase_diff_rms_rad, signal_character) =
        envelope_and_phase_profile(&normalized);

    let len = normalized.len();
    let mut spectrum: Vec<Complex64> = normalized
        .iter()
        .enumerate()
        .map(|(i, value)| {
            let w = if len > 1 {
                0.5 * (1.0 - (2.0 * PI * i as f64 / (len - 1) as f64).cos())
            } else {
                1.0
            };
            (*value - mean) * w
        })
        .collect();
    let mut planner = FftPlanner::<f64>::new();
    planner
        .plan_fft_forward(spectrum.len())
        .process(&mut spectrum);
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

    let noise_floor_power = median(&power);
    let max_bin_power = power.iter().copied().fold(0.0, f64::max);
    let estimated_snr_db = if noise_floor_power > 1e-18 && max_bin_power > 0.0 {
        10.0 * (max_bin_power / noise_floor_power).log10()
    } else {
        0.0
    };
    let sfdr_db = if peak_indices.len() >= 2 && power[peak_indices[1]] > 1e-18 {
        10.0 * (power[peak_indices[0]] / power[peak_indices[1]]).log10()
    } else {
        estimated_snr_db
    };
    let flatness = spectral_flatness(&power);
    let obw = occupied_bandwidth(&power, &frequencies);

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

    let (burst_count, burst_segments) = detect_bursts(&normalized);
    let spectrogram = compute_spectrogram(&normalized, mean);

    let mut anomaly_flags = Vec::new();
    let mut anomaly_score: u32 = 0;
    if dc_offset_ratio > 0.10 {
        anomaly_flags.push("elevated-dc-offset-lo-leakage");
        anomaly_score += 20;
    }
    if iq_gain_imbalance_db.abs() > 1.0 {
        anomaly_flags.push("iq-gain-imbalance");
        anomaly_score += 20;
    }
    if iq_phase_skew_deg.abs() > 5.0 {
        anomaly_flags.push("iq-quadrature-phase-skew");
        anomaly_score += 20;
    }
    if peak_indices.len() >= 2 && sfdr_db < 15.0 {
        anomaly_flags.push("strong-spurious-tone-low-sfdr");
        anomaly_score += 20;
    }
    if burst_count > 0 {
        anomaly_flags.push("transient-energy-burst-detected");
        anomaly_score += 20;
    }
    let anomaly_score = anomaly_score.min(100);

    let mut observations = if let Some(strongest) = spectral_peaks.first() {
        vec![format!(
            "Strongest spectral component: {:.6} {}, {:.4}% of measured spectral power (Hann-windowed).",
            strongest["frequency"].as_f64().unwrap_or_default(),
            unit,
            strongest["relative_power"].as_f64().unwrap_or_default() * 100.0
        )]
    } else {
        vec!["No non-zero spectral component was measured after mean removal.".to_owned()]
    };
    observations.push(format!("Signal character indicator: {signal_character}."));
    if !anomaly_flags.is_empty() {
        observations.push(format!(
            "Hardware/RF screening flagged {} indicator(s): {}.",
            anomaly_flags.len(),
            anomaly_flags.join(", ")
        ));
    }

    Ok(json!({
        "schema_version": 3,
        "analysis": "offline_iq_spectral_baseline",
        "input": {
            "sample_count": samples.len(),
            "sample_rate_hz": sample_rate
        },
        "metrics": {
            "mean_i": mean_i,
            "mean_q": mean_q,
            "dc_offset_magnitude": dc_offset_magnitude,
            "dc_offset_ratio": dc_offset_ratio,
            "rms_magnitude": rms,
            "peak_magnitude": peak,
            "crest_factor": if rms > 0.0 { peak / rms } else { 0.0 },
            "i_rms": i_rms_norm * scale,
            "q_rms": q_rms_norm * scale,
            "iq_gain_imbalance_db": iq_gain_imbalance_db,
            "iq_phase_skew_deg": iq_phase_skew_deg,
            "estimated_snr_db": estimated_snr_db,
            "sfdr_db": sfdr_db,
            "spectral_flatness": flatness,
            "spectral_entropy_bits": entropy,
            "occupied_bandwidth_99": obw,
            "envelope_kurtosis": envelope_kurtosis,
            "phase_diff_rms_rad": phase_diff_rms_rad,
            "signal_character": signal_character,
            "burst_count": burst_count,
            "anomaly_score": anomaly_score
        },
        "anomaly_flags": anomaly_flags,
        "burst_segments": burst_segments,
        "spectral_peaks": spectral_peaks,
        "preview": downsample_preview(samples, &frequencies, &power, spectrogram),
        "observations": observations,
        "limitations": [
            "These are offline signal measurements and RF impairment indicators, not proof of exploitability.",
            "Record instrument calibration, shielding, and authorization before drawing hardware conclusions.",
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
    fn detects_iq_imbalance_and_dc_offset() {
        let count = 256;
        let samples: Vec<Complex64> = (0..count)
            .map(|index| {
                let angle = 2.0 * PI * 10.0 * index as f64 / count as f64;
                Complex64::new(1.5 * angle.cos() + 0.5, 0.5 * angle.sin())
            })
            .collect();
        let report = analyze_samples(&samples, Some(256.0)).unwrap();
        assert!(report["metrics"]["iq_gain_imbalance_db"].as_f64().unwrap().abs() > 3.0);
        assert!(report["metrics"]["anomaly_score"].as_u64().unwrap() >= 40);
    }

    #[test]
    fn rejects_invalid_sample_rate() {
        let samples = vec![Complex64::new(1.0, 0.0); 4];
        assert!(analyze_samples(&samples, Some(0.0)).is_err());
    }
}
