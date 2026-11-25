from __future__ import annotations

import math
from typing import Any

import numpy as np
from numba import njit


@njit(cache=True)
def _time_domain_metrics(samples: np.ndarray) -> tuple[float, float, float, float]:
    sum_i = 0.0
    sum_q = 0.0
    sum_magnitude_squared = 0.0
    peak_magnitude = 0.0
    for sample in samples:
        i_value = sample.real
        q_value = sample.imag
        magnitude = math.sqrt(i_value * i_value + q_value * q_value)
        sum_i += i_value
        sum_q += q_value
        sum_magnitude_squared += magnitude * magnitude
        if magnitude > peak_magnitude:
            peak_magnitude = magnitude
    count = samples.size
    return (
        sum_i / count,
        sum_q / count,
        math.sqrt(sum_magnitude_squared / count),
        peak_magnitude,
    )


def analyze_samples(
    samples: np.ndarray,
    sample_rate: float | None = None,
) -> dict[str, Any]:
    """Calculate deterministic time-domain and FFT metrics for complex IQ samples."""
    samples = np.asarray(samples)
    if samples.ndim != 1:
        raise ValueError("IQ samples must be a one-dimensional array.")
    if samples.size < 2:
        raise ValueError("IQ input must contain at least two samples.")
    if sample_rate is not None and (not math.isfinite(sample_rate) or sample_rate <= 0):
        raise ValueError("Sample rate must be a finite positive number.")
    if not np.iscomplexobj(samples):
        raise ValueError("IQ samples must be complex-valued.")
    if not np.isfinite(samples.real).all() or not np.isfinite(samples.imag).all():
        raise ValueError("IQ input contains NaN or infinite values.")
    if not np.isfinite(np.abs(samples)).all():
        raise ValueError("IQ magnitudes exceed the supported numeric range.")
    samples = np.asarray(samples, dtype=np.complex128)

    scale = float(np.max(np.abs(samples)))
    normalized = samples / scale if scale else samples
    (
        mean_i_normalized,
        mean_q_normalized,
        rms_normalized,
        peak_normalized,
    ) = _time_domain_metrics(normalized)
    mean_i = mean_i_normalized * scale
    mean_q = mean_q_normalized * scale
    rms_magnitude = rms_normalized * scale
    peak_magnitude = peak_normalized * scale

    centered = normalized - np.mean(normalized)
    power = np.abs(np.fft.fftshift(np.fft.fft(centered))) ** 2
    total_power = float(np.sum(power))
    if total_power > 0 and power.size > 2:
        local_peaks = np.flatnonzero(
            (power >= np.roll(power, 1)) & (power > np.roll(power, -1))
        )
        peak_indices = sorted(local_peaks, key=lambda index: power[index], reverse=True)[:5]
    else:
        peak_indices = []

    sample_spacing = 1.0 / sample_rate if sample_rate is not None else 1.0
    frequencies = np.fft.fftshift(np.fft.fftfreq(samples.size, d=sample_spacing))
    frequency_unit = "Hz" if sample_rate is not None else "cycles/sample"
    spectral_peaks = [
        {
            "frequency": float(frequencies[index]),
            "unit": frequency_unit,
            "relative_power": float(power[index] / total_power),
        }
        for index in peak_indices
    ]

    if total_power > 0:
        probabilities = power[power > 0] / total_power
        spectral_entropy = float(-np.sum(probabilities * np.log2(probabilities)))
    else:
        spectral_entropy = 0.0

    observations = []
    if spectral_peaks:
        strongest = spectral_peaks[0]
        observations.append(
            "Strongest spectral component: "
            f"{strongest['frequency']:.6g} {frequency_unit}, "
            f"{strongest['relative_power']:.4%} of measured spectral power."
        )
    else:
        observations.append("No non-zero spectral component was measured after mean removal.")

    return {
        "schema_version": 1,
        "analysis": "offline_iq_spectral_baseline",
        "input": {
            "sample_count": int(samples.size),
            "sample_rate_hz": sample_rate,
        },
        "metrics": {
            "mean_i": mean_i,
            "mean_q": mean_q,
            "dc_offset_magnitude": math.hypot(mean_i, mean_q),
            "rms_magnitude": rms_magnitude,
            "peak_magnitude": peak_magnitude,
            "crest_factor": peak_magnitude / rms_magnitude if rms_magnitude else 0.0,
            "spectral_entropy_bits": spectral_entropy,
        },
        "spectral_peaks": spectral_peaks,
        "observations": observations,
        "limitations": [
            "These are signal measurements, not vulnerability findings.",
            "No reference capture or calibrated instrument metadata was supplied.",
            "IQ samples alone cannot establish a quantum-mechanical property or security impact.",
        ],
    }
