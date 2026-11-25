from __future__ import annotations

import csv
import hashlib
import math
from pathlib import Path
from typing import Any

import numpy as np

MAX_TRACE_BYTES = 256 * 1024 * 1024
MAX_TRACE_SAMPLES = 2_000_000


def _load_trace(path: Path) -> np.ndarray:
    if not path.is_file():
        raise FileNotFoundError(f"Measurement file not found: {path}")
    if path.stat().st_size > MAX_TRACE_BYTES:
        raise ValueError("Measurement file exceeds the 256 MiB size limit.")

    rows: list[list[float]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for line_number, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                row = [float(value) for value in next(csv.reader([stripped]))]
            except ValueError:
                if rows:
                    raise ValueError(f"Non-numeric measurement at line {line_number}.")
                continue
            if len(row) not in (1, 2):
                raise ValueError("Trace CSV must have one measurement column or time,measurement columns.")
            if rows and len(row) != len(rows[0]):
                raise ValueError(f"Inconsistent column count at line {line_number}.")
            rows.append(row)
            if len(rows) > MAX_TRACE_SAMPLES:
                raise ValueError(f"Trace exceeds the {MAX_TRACE_SAMPLES:,} sample limit.")

    if len(rows) < 3:
        raise ValueError("Measurement trace must contain at least three numeric samples.")
    values = np.asarray(rows, dtype=np.float64)
    if not np.isfinite(values).all():
        raise ValueError("Measurement trace contains NaN or infinite values.")
    measurements = values[:, -1]
    if float(np.max(np.abs(measurements))) > math.sqrt(np.finfo(np.float64).max) / 2:
        raise ValueError("Measurement values exceed the supported numeric range.")
    return measurements


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze_trace(
    path: Path,
    reference_path: Path | None = None,
    threshold: float = 6.0,
) -> dict[str, Any]:
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("Outlier threshold must be a finite positive number.")
    values = _load_trace(path)
    median = float(np.median(values))
    absolute_deviations = np.abs(values - median)
    mad = float(np.median(absolute_deviations))
    robust_sigma = 1.4826 * mad
    if robust_sigma:
        outlier_mask = absolute_deviations > threshold * robust_sigma
    else:
        outlier_mask = absolute_deviations > 0

    report: dict[str, Any] = {
        "schema_version": 1,
        "analysis": "offline_physical_measurement_trace",
        "input": {
            "name": path.name,
            "sample_count": int(values.size),
            "sha256": _file_sha256(path),
        },
        "metrics": {
            "mean": float(np.mean(values)),
            "median": median,
            "rms": float(np.sqrt(np.mean(np.square(values)))),
            "peak_absolute": float(np.max(np.abs(values))),
            "peak_to_peak": float(np.ptp(values)),
            "median_absolute_deviation": mad,
            "robust_outlier_threshold": threshold,
            "robust_outlier_count": int(np.count_nonzero(outlier_mask)),
            "robust_outlier_fraction": float(np.mean(outlier_mask)),
        },
        "observations": [
            f"Found {int(np.count_nonzero(outlier_mask))} robust statistical outlier(s) "
            f"using a {threshold:g} scaled-MAD threshold."
        ],
        "limitations": [
            "This is a generic measurement-trace screen, not a physical vulnerability test.",
            "Outliers may be valid events, sensor artifacts, or collection errors.",
            "No key extraction, device interaction, or exploit testing is performed.",
        ],
    }

    if reference_path is not None:
        reference = _load_trace(reference_path)
        reference_rms = float(np.sqrt(np.mean(np.square(reference))))
        current_rms = report["metrics"]["rms"]
        rms_ratio = current_rms / reference_rms if reference_rms else None
        if rms_ratio is not None and not math.isfinite(rms_ratio):
            rms_ratio = None
        report["reference"] = {
            "name": reference_path.name,
            "sample_count": int(reference.size),
            "sha256": _file_sha256(reference_path),
        }
        report["comparison"] = {
            "median_delta": median - float(np.median(reference)),
            "rms_delta": current_rms - reference_rms,
            "rms_ratio": rms_ratio,
            "peak_to_peak_delta": float(np.ptp(values)) - float(np.ptp(reference)),
        }
        report["limitations"].append(
            "Reference comparison uses aggregate statistics and does not establish causation."
        )

    return report
