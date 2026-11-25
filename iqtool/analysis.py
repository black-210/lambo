from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from .algorithms import analyze_samples

MAX_INPUT_BYTES = 256 * 1024 * 1024
MAX_SAMPLES = 2_000_000


def _read_csv(path: Path) -> np.ndarray:
    skiprows = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        for line_number, line in enumerate(stream, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                [float(value) for value in next(csv.reader([stripped]))]
            except ValueError:
                skiprows = line_number
            break

    try:
        values = np.loadtxt(
            path,
            delimiter=",",
            comments="#",
            skiprows=skiprows,
            dtype=np.float64,
            ndmin=2,
            encoding="utf-8-sig",
        )
    except (UnicodeDecodeError, ValueError) as error:
        raise ValueError("CSV must contain numeric I,Q columns, optionally with a header.") from error

    if values.ndim != 2 or values.shape[1] != 2:
        raise ValueError("CSV must have exactly two columns: I and Q.")
    return values[:, 0] + 1j * values[:, 1]


def load_iq(path: Path) -> np.ndarray:
    if not path.is_file():
        raise FileNotFoundError(f"IQ file not found: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"Input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB size limit.")

    suffix = path.suffix.lower()
    if suffix == ".csv":
        samples = _read_csv(path)
    elif suffix == ".npy":
        try:
            data = np.load(path, allow_pickle=False)
        except (OSError, ValueError) as error:
            raise ValueError("Could not read NPY file; object arrays are not supported.") from error
        if np.iscomplexobj(data) and data.ndim == 1:
            samples = data
        elif not np.iscomplexobj(data) and data.ndim == 2 and data.shape[1] == 2:
            samples = data[:, 0] + 1j * data[:, 1]
        else:
            raise ValueError("NPY must be a 1D complex array or a 2D real array with I,Q columns.")
    else:
        raise ValueError("Supported IQ formats are .csv and .npy.")

    if samples.size < 2:
        raise ValueError("IQ input must contain at least two samples.")
    if samples.size > MAX_SAMPLES:
        raise ValueError(f"Input exceeds the {MAX_SAMPLES:,} sample limit.")
    if not np.isfinite(samples.real).all() or not np.isfinite(samples.imag).all():
        raise ValueError("IQ input contains NaN or infinite values.")
    if not np.isfinite(np.abs(samples)).all():
        raise ValueError("IQ magnitudes exceed the supported numeric range.")
    return np.asarray(samples, dtype=np.complex128)


def analyze_iq(path: Path, sample_rate: float | None = None) -> dict[str, Any]:
    samples = load_iq(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    report = analyze_samples(samples, sample_rate)
    report["input"]["name"] = path.name
    report["input"]["sha256"] = digest.hexdigest()
    return report
