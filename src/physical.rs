use crate::common::{median, sha256_file, spectral_flatness};
use anyhow::{Context, Result, bail};
use csv::ReaderBuilder;
use num_complex::Complex64;
use rustfft::FftPlanner;
use serde_json::{Value, json};
use std::fs::File;
use std::path::Path;

const MAX_TRACE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRACE_SAMPLES: usize = 2_000_000;

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

fn moments(values: &[f64], mean: f64) -> (f64, f64, f64) {
    let n = values.len() as f64;
    let m2 = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
    let std_dev = m2.sqrt();
    if std_dev <= 1e-15 {
        return (0.0, 0.0, 0.0);
    }
    let m3 = values.iter().map(|v| ((v - mean) / std_dev).powi(3)).sum::<f64>() / n;
    let m4 = values.iter().map(|v| ((v - mean) / std_dev).powi(4)).sum::<f64>() / n;
    (std_dev, m3, m4 - 3.0)
}

struct PeriodicityResult {
    dominant_period: Option<f64>,
    periodic_power_ratio: f64,
    flatness: f64,
    harmonic_comb_count: usize,
    spectrum_bins: Vec<[f64; 2]>,
}

fn screen_periodicity(values: &[f64], mean: f64) -> PeriodicityResult {
    if values.len() < 8 {
        return PeriodicityResult {
            dominant_period: None,
            periodic_power_ratio: 0.0,
            flatness: 1.0,
            harmonic_comb_count: 0,
            spectrum_bins: Vec::new(),
        };
    }
    let mut buf: Vec<Complex64> = values
        .iter()
        .map(|v| Complex64::new(v - mean, 0.0))
        .collect();
    let mut planner = FftPlanner::<f64>::new();
    planner.plan_fft_forward(buf.len()).process(&mut buf);
    let half = buf.len() / 2;
    let ac_power: Vec<f64> = (1..=half).map(|k| buf[k].norm_sqr()).collect();
    let total_ac: f64 = ac_power.iter().sum();
    if total_ac <= 1e-18 || ac_power.is_empty() {
        return PeriodicityResult {
            dominant_period: None,
            periodic_power_ratio: 0.0,
            flatness: 1.0,
            harmonic_comb_count: 0,
            spectrum_bins: Vec::new(),
        };
    }
    let (best_idx, &best_pow) = ac_power
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(b.1))
        .unwrap();
    let fundamental_bin = best_idx + 1;
    let period = buf.len() as f64 / fundamental_bin as f64;
    let ratio = best_pow / total_ac;
    let flatness = spectral_flatness(&ac_power);

    let noise_floor = median(&ac_power).max(1e-24);
    let mut comb_count = 0_usize;
    for mult in 2..=5 {
        let h_bin = fundamental_bin * mult;
        if h_bin >= 1 && h_bin <= ac_power.len() && ac_power[h_bin - 1] > noise_floor * 8.0 {
            comb_count += 1;
        }
    }

    let max_p = best_pow.max(1e-24);
    let step = (ac_power.len() / 160).max(1);
    let spectrum_bins: Vec<[f64; 2]> = ac_power
        .iter()
        .enumerate()
        .step_by(step)
        .take(160)
        .map(|(idx, p)| {
            let norm_freq = (idx + 1) as f64 / buf.len() as f64;
            let db = 10.0 * (p / max_p).max(1e-12).log10();
            [norm_freq, db]
        })
        .collect();

    PeriodicityResult {
        dominant_period: Some(period),
        periodic_power_ratio: ratio,
        flatness,
        harmonic_comb_count: comb_count,
        spectrum_bins,
    }
}

fn autocorrelation_peak(values: &[f64], mean: f64) -> (Option<usize>, f64) {
    let n = values.len().min(4096);
    if n < 12 {
        return (None, 0.0);
    }
    let centered: Vec<f64> = values[..n].iter().map(|v| v - mean).collect();
    let energy: f64 = centered.iter().map(|v| v * v).sum();
    if energy <= 1e-18 {
        return (None, 0.0);
    }
    let mut best_lag = None;
    let mut best_r = 0.0_f64;
    for lag in 2..=(n / 2) {
        let cov: f64 = (0..(n - lag)).map(|i| centered[i] * centered[i + lag]).sum();
        let r = cov / energy;
        if r > best_r {
            best_r = r;
            best_lag = Some(lag);
        }
    }
    (best_lag, best_r.clamp(-1.0, 1.0))
}

fn rolling_variance_burst_ratio(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 24 {
        return 1.0;
    }
    let win = (n / 20).clamp(6, 256);
    let mut vars = Vec::new();
    for chunk in values.chunks(win) {
        if chunk.len() < 3 {
            continue;
        }
        let m = chunk.iter().sum::<f64>() / chunk.len() as f64;
        let v = chunk.iter().map(|x| (x - m).powi(2)).sum::<f64>() / chunk.len() as f64;
        vars.push(v);
    }
    if vars.is_empty() {
        return 1.0;
    }
    let med = median(&vars);
    let max_v = vars.iter().copied().fold(0.0_f64, f64::max);
    if med > 1e-15 { max_v / med } else { 1.0 }
}

fn detect_step_changes(values: &[f64], scale_sigma: f64) -> (usize, Option<usize>, f64) {
    let n = values.len();
    if n < 16 || scale_sigma <= 1e-15 {
        return (0, None, 0.0);
    }
    let win = (n / 16).clamp(4, 256);
    let mut shifts = 0_usize;
    let mut max_idx = None;
    let mut max_z = 0.0_f64;
    let mut i = win;
    while i + win <= n {
        let left = values[i - win..i].iter().sum::<f64>() / win as f64;
        let right = values[i..i + win].iter().sum::<f64>() / win as f64;
        let z = (right - left).abs() / scale_sigma;
        if z > 3.0 {
            shifts += 1;
        }
        if z > max_z {
            max_z = z;
            max_idx = Some(i);
        }
        i += win;
    }
    (shifts, max_idx, max_z)
}

fn pearson_correlation(a: &[f64], b: &[f64]) -> Option<f64> {
    let n = a.len().min(b.len());
    if n < 3 {
        return None;
    }
    let mean_a = a[..n].iter().sum::<f64>() / n as f64;
    let mean_b = b[..n].iter().sum::<f64>() / n as f64;
    let mut cov = 0.0;
    let mut va = 0.0;
    let mut vb = 0.0;
    for i in 0..n {
        let da = a[i] - mean_a;
        let db = b[i] - mean_b;
        cov += da * db;
        va += da * da;
        vb += db * db;
    }
    let denom = (va * vb).sqrt();
    if denom > 1e-15 {
        Some((cov / denom).clamp(-1.0, 1.0))
    } else {
        None
    }
}

fn welch_t_statistic(a: &[f64], mean_a: f64, std_a: f64, b: &[f64], mean_b: f64, std_b: f64) -> Option<f64> {
    let se_sq = (std_a * std_a) / a.len() as f64 + (std_b * std_b) / b.len() as f64;
    if se_sq > 1e-18 {
        Some((mean_a - mean_b) / se_sq.sqrt())
    } else {
        None
    }
}

pub fn analyze_trace(path: &Path, reference_path: Option<&Path>, threshold: f64) -> Result<Value> {
    if !threshold.is_finite() || threshold <= 0.0 {
        bail!("Outlier threshold must be a finite positive number.");
    }
    let values = load_trace(path)?;
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let center = median(&values);
    let deviations: Vec<f64> = values.iter().map(|value| (value - center).abs()).collect();
    let mad = median(&deviations);
    let robust_sigma = 1.4826 * mad;
    let (std_dev, skewness, excess_kurtosis) = moments(&values, mean);

    let mut glitch_events = Vec::new();
    let mut outlier_indices = Vec::new();
    for (idx, (&val, &dev)) in values.iter().zip(deviations.iter()).enumerate() {
        let is_outlier = if robust_sigma > 0.0 {
            dev > threshold * robust_sigma
        } else {
            dev > 0.0
        };
        if is_outlier {
            let score = if robust_sigma > 0.0 {
                dev / robust_sigma
            } else {
                f64::INFINITY
            };
            outlier_indices.push(idx);
            glitch_events.push((idx, val, score));
        }
    }
    let outliers = glitch_events.len();
    glitch_events.sort_by(|a, b| b.2.total_cmp(&a.2));
    glitch_events.truncate(25);
    let glitch_json: Vec<Value> = glitch_events
        .iter()
        .map(|(idx, val, score)| {
            json!({
                "sample_index": idx,
                "value": val,
                "mad_z_score": if score.is_finite() { json!(score) } else { json!(null) }
            })
        })
        .collect();

    let trace_rms = rms(&values);
    let peak_abs = values.iter().map(|value| value.abs()).fold(0.0, f64::max);
    let crest_factor = if trace_rms > 0.0 { peak_abs / trace_rms } else { 0.0 };

    let per = screen_periodicity(&values, mean);
    let (autocorr_lag, autocorr_peak) = autocorrelation_peak(&values, mean);
    let variance_burst_ratio = rolling_variance_burst_ratio(&values);
    let scale_for_shift = if robust_sigma > 0.0 { robust_sigma } else { std_dev };
    let (change_point_count, max_shift_idx, max_shift_sigma) =
        detect_step_changes(&values, scale_for_shift);

    let mut anomaly_flags = Vec::new();
    let mut anomaly_score: u32 = 0;
    if outliers > 0 {
        anomaly_flags.push("transient-glitch-outliers");
        anomaly_score += if outliers > 5 { 30 } else { 20 };
    }
    if per.periodic_power_ratio > 0.35 || autocorr_peak > 0.65 || per.harmonic_comb_count >= 2 {
        anomaly_flags.push("strong-periodic-clock-leakage");
        anomaly_score += 25;
    }
    if change_point_count > 0 || variance_burst_ratio > 6.0 {
        anomaly_flags.push("baseline-step-shift-or-localized-activity-burst");
        anomaly_score += 20;
    }
    if excess_kurtosis.abs() > 5.0 {
        anomaly_flags.push("heavy-tailed-impulsive-distribution");
        anomaly_score += 15;
    }

    let step = (values.len() / 300).max(1);
    let waveform_preview: Vec<[f64; 2]> = values
        .iter()
        .enumerate()
        .step_by(step)
        .take(300)
        .map(|(i, v)| [i as f64, *v])
        .collect();
    outlier_indices.truncate(50);

    let mut report = json!({
        "schema_version": 4,
        "analysis": "offline_physical_measurement_trace",
        "input": {
            "name": path.file_name().unwrap_or_default().to_string_lossy(),
            "sample_count": values.len(),
            "sha256": sha256_file(path)?
        },
        "metrics": {
            "mean": mean,
            "median": center,
            "std_dev": std_dev,
            "rms": trace_rms,
            "peak_absolute": peak_abs,
            "peak_to_peak": peak_to_peak(&values),
            "crest_factor": crest_factor,
            "skewness": skewness,
            "excess_kurtosis": excess_kurtosis,
            "median_absolute_deviation": mad,
            "robust_outlier_threshold": threshold,
            "robust_outlier_count": outliers,
            "robust_outlier_fraction": outliers as f64 / values.len() as f64,
            "dominant_period_samples": per.dominant_period,
            "periodic_power_ratio": per.periodic_power_ratio,
            "harmonic_comb_count": per.harmonic_comb_count,
            "autocorrelation_lag": autocorr_lag,
            "autocorrelation_peak": autocorr_peak,
            "variance_burst_ratio": variance_burst_ratio,
            "spectral_flatness": per.flatness,
            "change_point_count": change_point_count,
            "max_shift_index": max_shift_idx,
            "max_shift_sigma": max_shift_sigma,
            "anomaly_score": anomaly_score.min(100)
        },
        "anomaly_flags": anomaly_flags,
        "glitch_events": glitch_json,
        "preview": {
            "waveform": waveform_preview,
            "outlier_indices": outlier_indices,
            "spectrum_bins": per.spectrum_bins
        },
        "observations": [
            format!("Found {outliers} robust statistical outlier(s) using a {threshold:.2} scaled-MAD threshold."),
            format!("Periodic power ratio: {:.2}% (autocorr {:.2}, harmonic comb {}); variance burst ratio: {:.2}x.", per.periodic_power_ratio * 100.0, autocorr_peak, per.harmonic_comb_count, variance_burst_ratio)
        ],
        "limitations": [
            "This is a generic measurement-trace screen, not proof of a hardware exploit.",
            "Outliers or periodic harmonics may reflect normal clocks, sensor artifacts, or lab noise.",
            "No key extraction, active fault injection, or live device interaction is performed."
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
        let corr = pearson_correlation(&values, &reference);
        let ref_mean = reference.iter().sum::<f64>() / reference.len() as f64;
        let (ref_std, _, _) = moments(&reference, ref_mean);
        let welch_t = welch_t_statistic(&values, mean, std_dev, &reference, ref_mean, ref_std);
        let var_ratio = if ref_std > 1e-15 {
            Some((std_dev / ref_std).powi(2))
        } else {
            None
        };
        let mut div_score = 0_u32;
        if let Some(c) = corr
            && c < 0.7
        {
            div_score += 30;
        }
        if let Some(vr) = var_ratio
            && !(0.5..=2.0).contains(&vr)
        {
            div_score += 25;
        }
        if let Some(t) = welch_t
            && t.abs() > 4.5
        {
            div_score += 25;
        }
        if (center - median(&reference)).abs() > std_dev.max(ref_std) {
            div_score += 20;
        }

        report["reference"] = json!({
            "name": reference_path.file_name().unwrap_or_default().to_string_lossy(),
            "sample_count": reference.len(),
            "sha256": sha256_file(reference_path)?
        });
        report["comparison"] = json!({
            "median_delta": center - median(&reference),
            "rms_delta": trace_rms - reference_rms,
            "rms_ratio": ratio,
            "peak_to_peak_delta": peak_to_peak(&values) - peak_to_peak(&reference),
            "pearson_correlation": corr,
            "variance_ratio": var_ratio,
            "welch_t_statistic": welch_t,
            "tvla_threshold_exceeded": welch_t.is_some_and(|t| t.abs() > 4.5),
            "divergence_score": div_score.min(100)
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
    use std::f64::consts::PI;

    #[test]
    fn finds_single_outlier_in_constant_trace() {
        let path =
            std::env::temp_dir().join(format!("iq-workbench-trace-{}.csv", std::process::id()));
        fs::write(&path, "0\n0\n0\n0\n0\n0\n0\n0\n0\n100\n").unwrap();
        let report = analyze_trace(&path, None, 6.0).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report["metrics"]["robust_outlier_count"], 1);
    }

    #[test]
    fn screens_periodic_clock_component() {
        let path = std::env::temp_dir().join(format!(
            "iq-workbench-periodic-{}.csv",
            std::process::id()
        ));
        let mut content = String::new();
        for i in 0..128 {
            let v = (2.0 * PI * 8.0 * i as f64 / 128.0).sin();
            content.push_str(&format!("{v:.6}\n"));
        }
        fs::write(&path, content).unwrap();
        let report = analyze_trace(&path, None, 6.0).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(report["metrics"]["periodic_power_ratio"].as_f64().unwrap() > 0.8);
        assert!(report["metrics"]["autocorrelation_peak"].as_f64().unwrap() > 0.8);
    }
}
