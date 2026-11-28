use anyhow::{Context, Result, bail};
use ndarray::{Array1, Array2, Axis};
use num_complex::Complex64;
use rustfft::FftPlanner;
use std::f64::consts::PI;

// ═══════════════════════════════════════════════════════════════════
//  SECTION 1 – Basic statistical primitives
// ═══════════════════════════════════════════════════════════════════

/// Population mean.
#[inline]
pub fn mean(x: &[f64]) -> f64 {
    x.iter().sum::<f64>() / x.len() as f64
}

/// Population variance.
#[inline]
pub fn variance(x: &[f64]) -> f64 {
    let m = mean(x);
    x.iter().map(|v| (v - m).powi(2)).sum::<f64>() / x.len() as f64
}

/// Population standard deviation.
#[inline]
pub fn std_dev(x: &[f64]) -> f64 { variance(x).sqrt() }

/// Median Absolute Deviation – robust noise estimator.
pub fn mad(trace: &[f64]) -> f64 {
    let m = mean(trace);
    let mut devs: Vec<f64> = trace.iter().map(|v| (v - m).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = devs.len();
    if n % 2 == 0 { (devs[n / 2 - 1] + devs[n / 2]) / 2.0 } else { devs[n / 2] }
}

/// Skewness (third standardised moment).
pub fn skewness(x: &[f64]) -> f64 {
    let m = mean(x);
    let s = std_dev(x);
    if s == 0.0 { return 0.0; }
    x.iter().map(|v| ((v - m) / s).powi(3)).sum::<f64>() / x.len() as f64
}

/// Excess kurtosis (fourth standardised moment − 3).
pub fn kurtosis(x: &[f64]) -> f64 {
    let m = mean(x);
    let s = std_dev(x);
    if s == 0.0 { return 0.0; }
    x.iter().map(|v| ((v - m) / s).powi(4)).sum::<f64>() / x.len() as f64 - 3.0
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 2 – Glitch / Anomaly Detection
// ═══════════════════════════════════════════════════════════════════

/// CUSUM (Cumulative Sum) change‑point detector.
/// Returns the maximum absolute cumulative deviation and its sample index.
pub fn cusum(trace: &[f64]) -> (f64, usize) {
    let m = mean(trace);
    let mut cum = 0.0_f64;
    let mut best = (0.0_f64, 0usize);
    for (i, &v) in trace.iter().enumerate() {
        cum += v - m;
        if cum.abs() > best.0 { best = (cum.abs(), i); }
    }
    best
}

/// CUSUM with threshold: returns all change‑point indices where |cumsum| > threshold.
pub fn cusum_threshold(trace: &[f64], threshold: f64) -> Vec<usize> {
    let m = mean(trace);
    let mut cum = 0.0_f64;
    let mut hits = Vec::new();
    for (i, &v) in trace.iter().enumerate() {
        cum += v - m;
        if cum.abs() > threshold { hits.push(i); cum = 0.0; }
    }
    hits
}

/// Z‑score spike detector: returns indices with |z| > sigma_thresh.
pub fn zscore_spikes(trace: &[f64], sigma_thresh: f64) -> Vec<usize> {
    let m = mean(trace);
    let s = std_dev(trace);
    if s == 0.0 { return vec![]; }
    trace.iter().enumerate().filter_map(|(i, &v)| {
        if ((v - m) / s).abs() > sigma_thresh { Some(i) } else { None }
    }).collect()
}

/// Voltage‑glitch energy estimator (integral of |V(t) − V_nominal|² dt).
/// Models power consumed by an injected glitch pulse.
///
///   E_glitch = ∫ |V(t) − V₀|² / R  dt  ≈  Σ (vₙ − V₀)² · Δt / R
///
/// Returns energy in joules (or arbitrary units when R=1 Ω, Δt=1/sample_rate).
pub fn glitch_energy(trace: &[f64], v_nominal: f64, r_ohm: f64, sample_rate_hz: f64) -> f64 {
    let dt = 1.0 / sample_rate_hz;
    trace.iter().map(|&v| (v - v_nominal).powi(2) / r_ohm * dt).sum()
}

/// Clock‑jitter estimator via zero‑crossing analysis.
/// Returns (mean_period, jitter_sigma) in samples.
pub fn clock_jitter(trace: &[f64]) -> (f64, f64) {
    let m = mean(trace);
    let crossings: Vec<f64> = trace.windows(2).enumerate().filter_map(|(i, w)| {
        if (w[0] < m && w[1] >= m) || (w[0] > m && w[1] <= m) {
            // Linear interpolation for sub‑sample precision
            let frac = (m - w[0]) / (w[1] - w[0]);
            Some(i as f64 + frac)
        } else { None }
    }).collect();
    if crossings.len() < 2 { return (0.0, 0.0); }
    let periods: Vec<f64> = crossings.windows(2).map(|w| w[1] - w[0]).collect();
    (mean(&periods), std_dev(&periods))
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 3 – Side‑Channel Leakage Assessment
// ═══════════════════════════════════════════════════════════════════

/// Welch's t‑test TVLA: compares two sets of power traces point‑by‑point.
/// traces_a, traces_b: rows = measurements, cols = time samples.
/// Returns t‑statistic vector (one value per sample point).
pub fn tvla_welch(traces_a: &Array2<f64>, traces_b: &Array2<f64>) -> Result<Array1<f64>> {
    if traces_a.ncols() != traces_b.ncols() { bail!("TVLA: column count mismatch"); }
    let n_a = traces_a.nrows() as f64;
    let n_b = traces_b.nrows() as f64;
    let t: Vec<f64> = (0..traces_a.ncols()).map(|col| {
        let col_a: Vec<f64> = traces_a.column(col).to_vec();
        let col_b: Vec<f64> = traces_b.column(col).to_vec();
        let m_a = mean(&col_a); let m_b = mean(&col_b);
        let v_a = variance(&col_a); let v_b = variance(&col_b);
        let se = ((v_a / n_a) + (v_b / n_b)).sqrt();
        if se == 0.0 { 0.0 } else { (m_a - m_b) / se }
    }).collect();
    Ok(Array1::from(t))
}

/// Normalised Inter‑Class Variance (NICV).
/// `classes`: integer class label per row (trace).
/// Returns NICV vector (one value per sample point). Range [0, 1].
pub fn nicv(traces: &Array2<f64>, classes: &[usize]) -> Result<Array1<f64>> {
    if traces.nrows() != classes.len() { bail!("NICV: row/class count mismatch"); }
    let n_points = traces.ncols();
    let total_var: Vec<f64> = (0..n_points).map(|c| {
        let col: Vec<f64> = traces.column(c).to_vec();
        variance(&col)
    }).collect();
    // Unique classes
    let mut unique: Vec<usize> = classes.to_vec();
    unique.sort(); unique.dedup();
    let mut between = vec![0.0_f64; n_points];
    let n_total = traces.nrows() as f64;
    for cls in &unique {
        let indices: Vec<usize> = classes.iter().enumerate().filter_map(|(i, &c)| if c == *cls { Some(i) } else { None }).collect();
        let n_cls = indices.len() as f64;
        for c in 0..n_points {
            let col_all: Vec<f64> = traces.column(c).to_vec();
            let total_mean = mean(&col_all);
            let cls_vals: Vec<f64> = indices.iter().map(|&i| traces[[i, c]]).collect();
            let cls_mean = mean(&cls_vals);
            between[c] += (n_cls / n_total) * (cls_mean - total_mean).powi(2);
        }
    }
    let nicv_vec: Vec<f64> = between.iter().zip(total_var.iter()).map(|(b, t)| if *t == 0.0 { 0.0 } else { b / t }).collect();
    Ok(Array1::from(nicv_vec))
}

/// Signal‑to‑Noise Ratio (dB) using hypothesis vector H.
///   SNR(t) = Var_H[E[trace(t) | H]] / E_H[Var[trace(t) | H]]
pub fn snr_per_point(traces: &Array2<f64>, hypothesis: &[f64]) -> Result<Array1<f64>> {
    if traces.nrows() != hypothesis.len() { bail!("SNR: row/hypothesis length mismatch"); }
    // Bin traces by rounded hypothesis value
    let n_points = traces.ncols();
    let mut bins: std::collections::HashMap<i64, Vec<usize>> = std::collections::HashMap::new();
    for (i, &h) in hypothesis.iter().enumerate() {
        bins.entry((h * 1000.0) as i64).or_default().push(i);
    }
    let mut signal_var = vec![0.0_f64; n_points];
    let mut noise_sum = vec![0.0_f64; n_points];
    let n_bins = bins.len() as f64;
    for indices in bins.values() {
        for c in 0..n_points {
            let vals: Vec<f64> = indices.iter().map(|&i| traces[[i, c]]).collect();
            let m = mean(&vals);
            signal_var[c] += m; // collect means for inter‑class variance
            noise_sum[c] += variance(&vals);
        }
    }
    // Compute variance of per‑class means and mean of per‑class variances
    let grand_mean: Vec<f64> = signal_var.iter().map(|s| s / n_bins).collect();
    let result: Vec<f64> = grand_mean.iter().zip(noise_sum.iter()).map(|(sig, noise)| {
        let n = noise / n_bins;
        if n == 0.0 { 0.0 } else { 10.0 * (sig / n).log10() }
    }).collect();
    Ok(Array1::from(result))
}

/// Pearson cross‑correlation between two equal‑length signals.
pub fn pearson(a: &[f64], b: &[f64]) -> f64 {
    let ma = mean(a); let mb = mean(b);
    let num: f64 = a.iter().zip(b).map(|(x, y)| (x - ma) * (y - mb)).sum();
    let da: f64 = a.iter().map(|x| (x - ma).powi(2)).sum::<f64>().sqrt();
    let db: f64 = b.iter().map(|y| (y - mb).powi(2)).sum::<f64>().sqrt();
    if da == 0.0 || db == 0.0 { 0.0 } else { num / (da * db) }
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 4 – Differential Power Analysis (DPA / CPA)
// ═══════════════════════════════════════════════════════════════════

/// AES SubBytes lookup table (FIPS 197, Appendix A).
const AES_SBOX: [u8; 256] = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
];

/// Hamming weight of a byte.
pub fn hamming_weight(x: u8) -> f64 { x.count_ones() as f64 }

/// Hamming distance between two bytes.
pub fn hamming_distance(a: u8, b: u8) -> f64 { (a ^ b).count_ones() as f64 }

/// Hypothesis matrix for CPA against AES SubBytes.
/// Returns rows=num_traces × cols=256 matrix of Hamming weights.
pub fn aes_cpa_hypothesis(plaintexts: &[u8]) -> Array2<f64> {
    let n = plaintexts.len();
    let mut h = Array2::<f64>::zeros((n, 256));
    for (i, &p) in plaintexts.iter().enumerate() {
        for k in 0u16..256 {
            h[[i, k as usize]] = hamming_weight(AES_SBOX[(p ^ k as u8) as usize]);
        }
    }
    h
}

/// Full Correlation Power Analysis (CPA) over all 256 key guesses.
/// Returns (best_key_guess, best_correlation, corr_per_key).
pub fn cpa_attack(traces: &Array2<f64>, plaintexts: &[u8]) -> Result<(u8, f64, Vec<f64>)> {
    if traces.nrows() != plaintexts.len() { bail!("CPA: traces/plaintext length mismatch"); }
    let h = aes_cpa_hypothesis(plaintexts);
    let n_points = traces.ncols();
    let mut best_key = 0u8;
    let mut best_corr = 0.0_f64;
    let mut corr_per_key = vec![0.0_f64; 256];
    for k in 0..256usize {
        let hyp: Vec<f64> = h.column(k).to_vec();
        // Find max |pearson| over all time samples
        let max_corr = (0..n_points).map(|t| {
            let col: Vec<f64> = traces.column(t).to_vec();
            pearson(&col, &hyp).abs()
        }).fold(0.0_f64, f64::max);
        corr_per_key[k] = max_corr;
        if max_corr > best_corr { best_corr = max_corr; best_key = k as u8; }
    }
    Ok((best_key, best_corr, corr_per_key))
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 5 – EM / RF Electromagnetic Analysis
// ═══════════════════════════════════════════════════════════════════

/// Power Spectral Density via Welch's method (non‑overlapping segments).
pub fn welch_psd(trace: &[f64], segment_len: usize, sample_rate_hz: f64) -> Vec<(f64, f64)> {
    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(segment_len);
    let n_seg = trace.len() / segment_len;
    if n_seg == 0 { return vec![]; }
    let mut accum = vec![0.0_f64; segment_len / 2 + 1];
    for seg in 0..n_seg {
        let start = seg * segment_len;
        // Hann window
        let mut buf: Vec<Complex64> = (0..segment_len).map(|i| {
            let w = 0.5 * (1.0 - (2.0 * PI * i as f64 / (segment_len - 1) as f64).cos());
            Complex64::new(trace[start + i] * w, 0.0)
        }).collect();
        let mut scratch = vec![Complex64::new(0.0, 0.0); fft.get_inplace_scratch_len()];
        fft.process_with_scratch(&mut buf, &mut scratch);
        for (j, v) in buf.iter().take(segment_len / 2 + 1).enumerate() {
            accum[j] += v.norm_sqr();
        }
    }
    let scale = sample_rate_hz / (n_seg as f64 * segment_len as f64);
    (0..accum.len()).map(|i| {
        let freq = i as f64 * sample_rate_hz / segment_len as f64;
        (freq, accum[i] * scale)
    }).collect()
}

/// Clock harmonic detector: finds peaks in PSD at integer multiples of base_freq_hz.
/// Returns (harmonic_order, freq_hz, power_dBm) for found harmonics.
pub fn clock_harmonics(psd: &[(f64, f64)], base_freq_hz: f64, n_harmonics: usize, threshold_db: f64) -> Vec<(usize, f64, f64)> {
    let mut found = Vec::new();
    for order in 1..=n_harmonics {
        let target = base_freq_hz * order as f64;
        // Find closest PSD bin
        if let Some(&(freq, pwr)) = psd.iter().min_by(|a, b| {
            (a.0 - target).abs().partial_cmp(&(b.0 - target).abs()).unwrap()
        }) {
            let db = 10.0 * pwr.log10();
            if db > threshold_db { found.push((order, freq, db)); }
        }
    }
    found
}

/// EM near‑field leakage estimator using a dipole radiation model.
/// Estimates field strength at distance r from a radiating conductor.
///
///   E_field = (I₀ · f · L) / (4π · ε₀ · c² · r)   (simplified far‑field)
///
/// Returns estimated E‑field in V/m.
pub fn em_leakage_estimate(current_a: f64, freq_hz: f64, antenna_len_m: f64, distance_m: f64) -> f64 {
    let epsilon_0 = 8.854_187_817e-12_f64;
    let c = 299_792_458.0_f64;
    (current_a * freq_hz * antenna_len_m) / (4.0 * PI * epsilon_0 * c * c * distance_m)
}

/// Channel capacity (Shannon‑Hartley theorem):
///   C = B · log₂(1 + S/N)
/// Returns capacity in bits/second.
pub fn shannon_capacity(bandwidth_hz: f64, snr_linear: f64) -> f64 {
    bandwidth_hz * (1.0 + snr_linear).log2()
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 6 – Physical Fault Injection Models
// ═══════════════════════════════════════════════════════════════════

/// Voltage fault injection success probability model.
/// Based on the empirical model: P_fault = sigmoid((V_drop − V_threshold) / sigma)
/// where V_drop is the glitch amplitude, V_threshold and sigma are device parameters.
pub fn fault_probability(v_drop: f64, v_threshold: f64, sigma: f64) -> f64 {
    1.0 / (1.0 + (-(v_drop - v_threshold) / sigma).exp())
}

/// Minimum glitch energy required to cause a bit‑flip in a CMOS gate.
///   E_min = ½ · C · V_dd² (charge stored on gate capacitance)
///
/// Returns minimum energy in joules.
pub fn cmos_bit_flip_energy(capacitance_f: f64, v_dd: f64) -> f64 {
    0.5 * capacitance_f * v_dd * v_dd
}

/// Electromagnetic pulse (EMP) induced voltage on a PCB trace.
///   V_induced = −M · dI/dt
/// where M is mutual inductance, dI/dt is the EMP current rate.
///
/// Returns induced voltage in volts.
pub fn emp_induced_voltage(mutual_inductance_h: f64, di_dt_a_per_s: f64) -> f64 {
    -mutual_inductance_h * di_dt_a_per_s
}

/// Power glitch detection risk score (composite metric, 0–100).
/// Combines MAD, CUSUM, and Z‑score spike count into a normalised risk index.
pub fn glitch_risk_score(trace: &[f64], sigma_thresh: f64) -> f64 {
    let mad_val = mad(trace);
    let (cusum_max, _) = cusum(trace);
    let n_spikes = zscore_spikes(trace, sigma_thresh).len() as f64;
    let s = std_dev(trace);
    if s == 0.0 { return 0.0; }
    let norm_mad = (mad_val / s).min(1.0);
    let norm_cusum = (cusum_max / (s * trace.len() as f64)).min(1.0);
    let norm_spikes = (n_spikes / trace.len() as f64).min(1.0);
    (norm_mad * 30.0 + norm_cusum * 40.0 + norm_spikes * 30.0).min(100.0)
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 7 – Template Attack
// ═══════════════════════════════════════════════════════════════════

/// Template: mean trace + covariance matrix for a single class.
#[derive(Clone, Debug)]
pub struct Template {
    pub class_key: u8,
    pub mean_trace: Array1<f64>,
    pub cov: Array2<f64>,
}

/// Build templates from labelled training traces.
pub fn build_templates(traces: &Array2<f64>, keys: &[u8]) -> Result<Vec<Template>> {
    let mut unique_keys: Vec<u8> = keys.to_vec();
    unique_keys.sort(); unique_keys.dedup();
    let n_points = traces.ncols();
    let mut templates = Vec::new();
    for &k in &unique_keys {
        let indices: Vec<usize> = keys.iter().enumerate().filter_map(|(i, &kk)| if kk == k { Some(i) } else { None }).collect();
        let n = indices.len() as f64;
        // Mean
        let mut mean_t = Array1::<f64>::zeros(n_points);
        for &i in &indices { mean_t = mean_t + traces.row(i).to_owned(); }
        mean_t /= n;
        // Covariance
        let mut cov = Array2::<f64>::zeros((n_points, n_points));
        for &i in &indices {
            let d = traces.row(i).to_owned() - &mean_t;
            cov = cov + d.view().insert_axis(Axis(1)).dot(&d.view().insert_axis(Axis(0)));
        }
        cov /= (n - 1.0).max(1.0);
        templates.push(Template { class_key: k, mean_trace: mean_t, cov });
    }
    Ok(templates)
}

/// Match a single observed trace against all templates using log‑likelihood.
/// Returns the best key guess and the log‑likelihood.
pub fn match_template(observed: &Array1<f64>, templates: &[Template]) -> (u8, f64) {
    let mut best_key = 0u8;
    let mut best_ll = f64::NEG_INFINITY;
    for t in templates {
        let d = observed - &t.mean_trace;
        // Gaussian log‑likelihood (ignoring constant determinant term for ranking)
        let cov_diag: Vec<f64> = (0..d.len()).map(|i| t.cov[[i, i]]).collect();
        let ll = d.iter().zip(&cov_diag).map(|(di, ci)| {
            if *ci <= 0.0 { 0.0 } else { -0.5 * di.powi(2) / ci }
        }).sum::<f64>();
        if ll > best_ll { best_ll = ll; best_key = t.class_key; }
    }
    (best_key, best_ll)
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 8 – X86 / ARM Architecture Fingerprinting
// ═══════════════════════════════════════════════════════════════════

/// x86 CPUID‑style architecture features reported by the OS.
#[derive(Debug, serde::Serialize)]
pub struct CpuFeatures {
    pub arch: String,
    pub vendor: String,
    pub model_name: String,
    pub cores: usize,
    pub has_rdrand: bool,
    pub has_aes_ni: bool,
    pub has_avx: bool,
    pub has_avx2: bool,
    pub has_sgx: bool,
    pub cache_l1d_kb: Option<usize>,
    pub cache_l2_kb: Option<usize>,
    pub cache_l3_kb: Option<usize>,
}

/// Passive CPU feature fingerprint using /proc/cpuinfo (Linux) or WMIC (Windows).
pub fn fingerprint_cpu() -> CpuFeatures {
    #[cfg(target_os = "windows")]
    return fingerprint_cpu_windows();
    #[cfg(not(target_os = "windows"))]
    return fingerprint_cpu_linux();
}

#[cfg(target_os = "windows")]
fn fingerprint_cpu_windows() -> CpuFeatures {
    use std::process::Command;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-WmiObject Win32_Processor | Select-Object Architecture,Manufacturer,Name,NumberOfCores | ConvertTo-Json -Compress"])
        .output()
        .unwrap_or_else(|_| std::process::Output { status: std::process::ExitStatus::default(), stdout: vec![], stderr: vec![] });
    let text = String::from_utf8_lossy(&out.stdout);
    let j: serde_json::Value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    let arch_code = j["Architecture"].as_u64().unwrap_or(0);
    let arch = match arch_code { 0 => "x86", 9 => "x86_64", 12 => "ARM64", _ => "unknown" }.to_string();
    CpuFeatures {
        arch,
        vendor: j["Manufacturer"].as_str().unwrap_or("unknown").to_string(),
        model_name: j["Name"].as_str().unwrap_or("unknown").to_string(),
        cores: j["NumberOfCores"].as_u64().unwrap_or(1) as usize,
        // These flags require CPUID in real use – placeholders here:
        has_rdrand: false, has_aes_ni: false, has_avx: false, has_avx2: false, has_sgx: false,
        cache_l1d_kb: None, cache_l2_kb: None, cache_l3_kb: None,
    }
}

#[cfg(not(target_os = "windows"))]
fn fingerprint_cpu_linux() -> CpuFeatures {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let get = |key: &str| -> String {
        cpuinfo.lines().find(|l| l.starts_with(key))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };
    let flags = get("flags");
    CpuFeatures {
        arch: if cfg!(target_arch = "x86_64") { "x86_64".into() } else { "aarch64".into() },
        vendor: get("vendor_id"),
        model_name: get("model name"),
        cores: get("cpu cores").parse().unwrap_or(1),
        has_rdrand: flags.contains("rdrand"),
        has_aes_ni: flags.contains("aes"),
        has_avx:    flags.contains("avx"),
        has_avx2:   flags.contains("avx2"),
        has_sgx:    flags.contains("sgx"),
        cache_l1d_kb: get("cache size").split_whitespace().next().and_then(|s| s.parse().ok()),
        cache_l2_kb: None,
        cache_l3_kb: None,
    }
}

// ═══════════════════════════════════════════════════════════════════
//  SECTION 9 – Unit Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::array;

    #[test]
    fn test_basic_stats() {
        let d = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((mean(&d) - 3.0).abs() < 1e-12);
        assert!((variance(&d) - 2.0).abs() < 1e-12);
        assert!((std_dev(&d) - 2.0_f64.sqrt()).abs() < 1e-12);
    }

    #[test]
    fn test_mad() {
        let d = vec![1.0, 1.0, 1.0, 1.0, 10.0]; // outlier at 10
        assert!(mad(&d) > 0.0);
    }

    #[test]
    fn test_cusum_spike() {
        let mut trace = vec![0.0_f64; 100];
        trace[50] = 100.0; // hard spike -> max |cumsum| right at change-point boundary
        let (val, idx) = cusum(trace.as_slice());
        assert!(idx == 49 || idx == 50);
        assert!(val >= 50.0);
    }

    #[test]
    fn test_zscore_spikes() {
        let mut trace = vec![0.0_f64; 50];
        trace[25] = 100.0;
        let spikes = zscore_spikes(&trace, 2.0);
        assert!(spikes.contains(&25));
    }

    #[test]
    fn test_tvla_shape() {
        let a = array![[1.0, 2.0, 3.0], [1.1, 2.1, 3.1]];
        let b = array![[2.0, 1.0, 0.5], [2.1, 0.9, 0.6]];
        let t = tvla_welch(&a, &b).unwrap();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn test_glitch_energy() {
        let trace = vec![3.3_f64; 100]; // constant 3.3V = nominal
        let e = glitch_energy(&trace, 3.3, 50.0, 1e6);
        assert!(e < 1e-10); // near zero
    }

    #[test]
    fn test_fault_probability() {
        // At threshold, probability should be 0.5
        let p = fault_probability(1.5, 1.5, 0.1);
        assert!((p - 0.5).abs() < 1e-12);
    }

    #[test]
    fn test_cpa_sbox() {
        // Build random traces correlated with Hamming weight of AES output
        use ndarray::Array2;
        let n_traces = 50;
        let n_points = 10;
        let key = 42u8;
        let plaintexts: Vec<u8> = (0u8..50).collect();
        let mut traces = Array2::<f64>::zeros((n_traces, n_points));
        for (i, &p) in plaintexts.iter().enumerate() {
            let hw = hamming_weight(AES_SBOX[(p ^ key) as usize]);
            for j in 0..n_points { traces[[i, j]] = hw + (i as f64 * 0.001); }
        }
        let (best_key, best_corr, _) = cpa_attack(&traces, &plaintexts).unwrap();
        assert_eq!(best_key, key);
        assert!(best_corr > 0.9);
    }

    #[test]
    fn test_shannon_capacity() {
        // 20 MHz BW, SNR = 100 ≈ 20 dB → ~133 Mbps
        let c = shannon_capacity(20e6, 100.0);
        assert!(c > 100e6);
    }

    #[test]
    fn test_clock_jitter() {
        // Synthetic 1 kHz sine wave at 1 MHz sample rate
        let sr = 1_000_000.0_f64;
        let freq = 1_000.0_f64;
        let trace: Vec<f64> = (0..10_000).map(|i| (2.0 * PI * freq * i as f64 / sr).sin()).collect();
        let (period, jitter) = clock_jitter(&trace);
        assert!((period - sr / freq / 2.0).abs() < 5.0); // half‑period crossings
        assert!(jitter < 5.0);
    }
}
