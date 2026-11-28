use anyhow::Result;
use num_complex::Complex64;
use rustfft::FftPlanner;
use serde::Serialize;
use std::f64::consts::PI;

// ═══════════════════════════════════════════════════════════════════
//  RF Analysis – Spectrum, IQ, Demodulation, Anomaly Detection
// ═══════════════════════════════════════════════════════════════════

/// Magnitude spectrum from IQ samples using FFT.
/// Returns (frequency_hz, magnitude) pairs.
pub fn magnitude_spectrum(iq: &[Complex64], sample_rate_hz: f64) -> Vec<(f64, f64)> {
    if iq.is_empty() { return vec![]; }
    let n = iq.len().next_power_of_two();
    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(n);
    let mut buf: Vec<Complex64> = iq.iter().copied().collect();
    buf.resize(n, Complex64::new(0.0, 0.0));
    let mut scratch = vec![Complex64::new(0.0, 0.0); fft.get_inplace_scratch_len()];
    fft.process_with_scratch(&mut buf, &mut scratch);
    // FFT shift: negative frequencies first
    let mut result = Vec::with_capacity(n);
    let half = n / 2;
    for i in 0..n {
        let shifted = (i + half) % n;
        let freq = ((i as f64 - half as f64) / n as f64) * sample_rate_hz;
        result.push((freq, buf[shifted].norm()));
    }
    result
}

/// Spectrogram: rows = time, cols = frequency.
/// Returns (time_s, freq_hz, magnitude) flattened.
pub fn spectrogram(
    iq: &[Complex64],
    window: usize,
    hop: usize,
    sample_rate_hz: f64,
) -> Vec<(f64, f64, f64)> {
    if iq.is_empty() || window == 0 { return vec![]; }
    let mut planner = FftPlanner::<f64>::new();
    let fft = planner.plan_fft_forward(window);
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut time_idx = 0usize;
    while offset + window <= iq.len() {
        let time_s = (offset as f64) / sample_rate_hz;
        let mut buf: Vec<Complex64> = (0..window).map(|i| {
            // Hann window
            let w = 0.5 * (1.0 - (2.0 * PI * i as f64 / (window - 1) as f64).cos());
            Complex64::new(iq[offset + i].re * w, iq[offset + i].im * w)
        }).collect();
        let mut scratch = vec![Complex64::new(0.0, 0.0); fft.get_inplace_scratch_len()];
        fft.process_with_scratch(&mut buf, &mut scratch);
        let half = window / 2;
        for i in 0..window {
            let shifted = (i + half) % window;
            let freq = ((i as f64 - half as f64) / window as f64) * sample_rate_hz;
            result.push((time_s, freq, buf[shifted].norm()));
        }
        offset += hop;
        time_idx += 1;
    }
    result
}

/// Signal power in dBm assuming 50 Ω load.
///   P_dBm = 10 · log₁₀(P_mW) = 10 · log₁₀(|IQ|² / (2 · R) · 1000)
pub fn power_dbm(iq: &[Complex64], r_ohm: f64) -> f64 {
    if iq.is_empty() { return f64::NEG_INFINITY; }
    let mean_sq = iq.iter().map(|c| c.norm_sqr()).sum::<f64>() / iq.len() as f64;
    let p_mw = mean_sq / (2.0 * r_ohm) * 1000.0;
    10.0 * p_mw.log10()
}

/// SNR estimate from signal region vs noise floor.
/// `signal_bins` and `noise_bins` are frequency index ranges in the FFT output.
pub fn snr_db_from_spectrum(
    spectrum_mags: &[f64],
    signal_bins: std::ops::Range<usize>,
    noise_bins: std::ops::Range<usize>,
) -> f64 {
    let sig: f64 = spectrum_mags[signal_bins.start..signal_bins.end.min(spectrum_mags.len())]
        .iter().map(|v| v * v).sum::<f64>();
    let noise: f64 = spectrum_mags[noise_bins.start..noise_bins.end.min(spectrum_mags.len())]
        .iter().map(|v| v * v).sum::<f64>();
    if noise == 0.0 { return 0.0; }
    10.0 * (sig / noise).log10()
}

/// Channel occupancy: fraction of spectrum bins above threshold.
pub fn channel_occupancy(spectrum_mags: &[f64], threshold: f64) -> f64 {
    if spectrum_mags.is_empty() { return 0.0; }
    let above = spectrum_mags.iter().filter(|&&v| v > threshold).count();
    above as f64 / spectrum_mags.len() as f64
}

/// AM demodulator – returns envelope (Hilbert magnitude approximation).
pub fn demod_am(iq: &[Complex64]) -> Vec<f64> {
    iq.iter().map(|c| c.norm()).collect()
}

/// FM demodulator – instantaneous frequency via differential phase.
///   f_inst(n) = (phase(n) − phase(n−1)) · fs / (2π)
pub fn demod_fm(iq: &[Complex64], sample_rate_hz: f64) -> Vec<f64> {
    if iq.len() < 2 { return vec![]; }
    iq.windows(2).map(|w| {
        let d = w[1] * w[0].conj();
        d.arg() * sample_rate_hz / (2.0 * PI)
    }).collect()
}

/// Phase demodulator.
pub fn demod_pm(iq: &[Complex64]) -> Vec<f64> {
    iq.iter().map(|c| c.arg()).collect()
}

/// IQ imbalance estimator.
/// Returns (amplitude_imbalance_dB, phase_imbalance_deg).
///   - amplitude: ratio of I_rms to Q_rms
///   - phase: average phase angle deviation from 90°
pub fn iq_imbalance(iq: &[Complex64]) -> (f64, f64) {
    if iq.is_empty() { return (0.0, 0.0); }
    let i_rms = (iq.iter().map(|c| c.re.powi(2)).sum::<f64>() / iq.len() as f64).sqrt();
    let q_rms = (iq.iter().map(|c| c.im.powi(2)).sum::<f64>() / iq.len() as f64).sqrt();
    let amp_db = if q_rms == 0.0 { 0.0 } else { 20.0 * (i_rms / q_rms).log10() };
    // Phase imbalance: mean phase of samples (should be 0 for balanced IQ)
    let mean_phase_deg = iq.iter().map(|c| c.arg().to_degrees()).sum::<f64>() / iq.len() as f64;
    (amp_db, mean_phase_deg)
}

/// Carrier frequency offset (CFO) estimate via spectral peak detection.
/// Returns estimated CFO in Hz.
pub fn cfo_estimate(iq: &[Complex64], sample_rate_hz: f64) -> f64 {
    let spec = magnitude_spectrum(iq, sample_rate_hz);
    spec.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap())
        .map(|(f, _)| *f)
        .unwrap_or(0.0)
}

/// Bit Error Rate estimator under AWGN:
///   BER_BPSK = Q(√(2·Eb/N0)) ≈ ½ · erfc(√(Eb/N0))
/// Returns approximate BER for BPSK modulation.
pub fn ber_bpsk(snr_db: f64) -> f64 {
    let snr_lin = 10.0_f64.powf(snr_db / 10.0);
    // Q-function approximation: Q(x) ≈ exp(−x²/2) / (x · √(2π))
    let x = snr_lin.sqrt();
    if x < 1e-9 { return 0.5; }
    let q = (-x * x / 2.0).exp() / (x * (2.0 * PI).sqrt());
    q.min(0.5)
}

/// RF propagation path loss (Friis formula, free space):
///   PL(dB) = 20·log₁₀(4π·d·f / c)
/// Returns path loss in dB.
pub fn friis_path_loss_db(distance_m: f64, freq_hz: f64) -> f64 {
    let c = 299_792_458.0_f64;
    20.0 * (4.0 * PI * distance_m * freq_hz / c).log10()
}

/// Link budget calculator.
/// Returns received power in dBm.
///   P_rx = P_tx + G_tx + G_rx − PL − losses
pub fn link_budget_dbm(
    p_tx_dbm: f64,
    gain_tx_dbi: f64,
    gain_rx_dbi: f64,
    path_loss_db: f64,
    other_losses_db: f64,
) -> f64 {
    p_tx_dbm + gain_tx_dbi + gain_rx_dbi - path_loss_db - other_losses_db
}

/// Radar cross section (RCS) model for detecting objects via backscatter.
/// Returns received power in watts.
///   P_rx = (P_tx · G² · λ² · σ_rcs) / ((4π)³ · R⁴)
pub fn radar_received_power(
    p_tx_w: f64,
    gain_linear: f64,
    wavelength_m: f64,
    rcs_m2: f64,
    range_m: f64,
) -> f64 {
    let four_pi_cubed = (4.0 * PI).powi(3);
    (p_tx_w * gain_linear.powi(2) * wavelength_m.powi(2) * rcs_m2)
        / (four_pi_cubed * range_m.powi(4))
}

/// Detect RF jamming by comparing signal-to-noise ratio against baseline.
/// Returns (is_jammed, confidence 0–1, estimated jammer_power_dbm).
pub fn detect_jamming(
    current_snr_db: f64,
    baseline_snr_db: f64,
    snr_threshold_db: f64,
) -> (bool, f64, f64) {
    let degradation = baseline_snr_db - current_snr_db;
    let is_jammed = degradation > snr_threshold_db;
    let confidence = (degradation / (snr_threshold_db * 2.0)).min(1.0).max(0.0);
    let jammer_power_estimate = baseline_snr_db - current_snr_db + 10.0; // rough model
    (is_jammed, confidence, jammer_power_estimate)
}

/// Detect RF replay by cross-correlating current frame with a stored template.
pub fn detect_replay(frame: &[Complex64], template: &[Complex64]) -> (bool, f64) {
    if frame.is_empty() || template.is_empty() { return (false, 0.0); }
    let min_len = frame.len().min(template.len());
    // Normalised cross-correlation at zero lag
    let dot: f64 = frame[..min_len].iter().zip(&template[..min_len])
        .map(|(a, b)| a.re * b.re + a.im * b.im).sum();
    let norm_a: f64 = frame[..min_len].iter().map(|c| c.norm_sqr()).sum::<f64>().sqrt();
    let norm_b: f64 = template[..min_len].iter().map(|c| c.norm_sqr()).sum::<f64>().sqrt();
    let corr = if norm_a == 0.0 || norm_b == 0.0 { 0.0 } else { dot / (norm_a * norm_b) };
    (corr > 0.85, corr.max(0.0))
}

/// Full RF scan summary report.
#[derive(Debug, Serialize)]
pub struct RfScanReport {
    pub center_freq_hz: f64,
    pub sample_rate_hz: f64,
    pub n_samples: usize,
    pub power_dbm: f64,
    pub cfo_hz: f64,
    pub iq_amp_imbalance_db: f64,
    pub iq_phase_imbalance_deg: f64,
    pub channel_occupancy_pct: f64,
    pub is_jammed: bool,
    pub jam_confidence: f64,
    pub estimated_jammer_power_dbm: f64,
    pub path_loss_db: Option<f64>,
    pub link_margin_db: Option<f64>,
}

pub fn rf_scan(
    iq: &[Complex64],
    center_freq_hz: f64,
    sample_rate_hz: f64,
    baseline_snr_db: f64,
) -> RfScanReport {
    let spec = magnitude_spectrum(iq, sample_rate_hz);
    let mags: Vec<f64> = spec.iter().map(|(_, m)| *m).collect();
    let mean_mag = if mags.is_empty() { 0.0 } else { mags.iter().sum::<f64>() / mags.len() as f64 };
    let n = mags.len();
    let signal_range = (n / 4)..(3 * n / 4);
    let noise_range = 0..(n / 10);
    let snr = snr_db_from_spectrum(&mags, signal_range, noise_range);
    let p_dbm = power_dbm(iq, 50.0);
    let cfo = cfo_estimate(iq, sample_rate_hz);
    let (amp_imb, phase_imb) = iq_imbalance(iq);
    let occ = channel_occupancy(&mags, mean_mag * 2.0);
    let (is_jammed, conf, jam_pwr) = detect_jamming(snr, baseline_snr_db, 10.0);
    RfScanReport {
        center_freq_hz,
        sample_rate_hz,
        n_samples: iq.len(),
        power_dbm: p_dbm,
        cfo_hz: cfo,
        iq_amp_imbalance_db: amp_imb,
        iq_phase_imbalance_deg: phase_imb,
        channel_occupancy_pct: occ * 100.0,
        is_jammed,
        jam_confidence: conf,
        estimated_jammer_power_dbm: jam_pwr,
        path_loss_db: None,
        link_margin_db: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sine_iq(n: usize, freq_hz: f64, sr: f64) -> Vec<Complex64> {
        (0..n).map(|i| {
            let t = i as f64 / sr;
            Complex64::new((2.0 * PI * freq_hz * t).cos(), (2.0 * PI * freq_hz * t).sin())
        }).collect()
    }

    #[test]
    fn spectrum_peak_at_signal() {
        let sr = 1_000_000.0_f64;
        let iq = sine_iq(4096, 100_000.0, sr);
        let spec = magnitude_spectrum(&iq, sr);
        let peak = spec.iter().max_by(|a, b| a.1.partial_cmp(&b.1).unwrap()).unwrap();
        assert!((peak.0.abs() - 100_000.0).abs() < 50_000.0);
    }

    #[test]
    fn power_dbm_range() {
        let iq = sine_iq(1024, 1000.0, 1e6);
        let p = power_dbm(&iq, 50.0);
        assert!(p > -60.0 && p < 20.0);
    }

    #[test]
    fn fm_demod_non_empty() {
        let iq = sine_iq(1024, 1000.0, 1e6);
        let fm = demod_fm(&iq, 1e6);
        assert_eq!(fm.len(), iq.len() - 1);
    }

    #[test]
    fn friis_path_loss() {
        let pl = friis_path_loss_db(100.0, 2.4e9);
        assert!(pl > 60.0 && pl < 90.0);
    }

    #[test]
    fn detect_replay_identical() {
        let iq = sine_iq(512, 1000.0, 1e6);
        let (is_replay, corr) = detect_replay(&iq, &iq);
        assert!(is_replay);
        assert!((corr - 1.0).abs() < 1e-6);
    }

    #[test]
    fn ber_bpsk_at_high_snr() {
        let ber = ber_bpsk(20.0);
        assert!(ber < 1e-3);
    }

    #[test]
    fn rf_scan_runs() {
        let iq = sine_iq(4096, 100_000.0, 1e6);
        let report = rf_scan(&iq, 433.92e6, 1e6, 30.0);
        assert!(report.power_dbm.is_finite());
    }
}
