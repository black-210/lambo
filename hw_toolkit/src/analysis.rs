use anyhow::Result;
use rustfft::{FftPlanner, num_complex::Complex};
use ndarray::Array2;
use rayon::prelude::*;
use num_complex::Complex64;

/// Compute magnitude spectrogram from IQ samples.
pub fn spectrogram(iq: &[Complex64], window: usize, hop: usize) -> Result<Vec<Vec<f32>>> {
    let mut planner = FftPlanner::<f32>::new();
    let fft = planner.plan_fft_forward(window);
    let mut spec = Vec::new();
    let mut offset = 0usize;
    while offset + window <= iq.len() {
        let mut buf: Vec<Complex<f32>> = iq[offset..offset+window]
            .iter()
            .map(|c| Complex { re: c.re as f32, im: c.im as f32 })
            .collect();
        buf.resize(window, Complex::zero());
        fft.process(&mut buf);
        let mags: Vec<f32> = buf.iter().map(|c| (c.re.powi(2) + c.im.powi(2)).sqrt()).collect();
        spec.push(mags);
        offset += hop;
    }
    Ok(spec)
}

/// Pearson correlation for side‑channel power traces.
pub fn power_trace_correlation(trace: &[f64], hypothesis: &[f64]) -> f64 {
    let n = trace.len() as f64;
    let mean_t = trace.iter().copied().sum::<f64>() / n;
    let mean_h = hypothesis.iter().copied().sum::<f64>() / n;
    let cov = trace.iter().zip(hypothesis).map(|(a, b)| (a - mean_t) * (b - mean_h)).sum::<f64>() / n;
    let var_t = trace.iter().map(|a| (a - mean_t).powi(2)).sum::<f64>() / n;
    let var_h = hypothesis.iter().map(|b| (b - mean_h).powi(2)).sum::<f64>() / n;
    cov / (var_t.sqrt() * var_h.sqrt())
}
