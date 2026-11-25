# IQ Research CLI

A small, offline-first starting point for examining **authorized IQ recordings**.
It computes reproducible signal measurements and can optionally explain a saved
report through an AI provider. It does not transmit RF, interact with targets, or
determine that a capture contains a security or quantum-mechanical vulnerability.

## Project layout

```text
main.py                 CLI entry point
iqtool/
  analysis.py           IQ file loading, validation, and report provenance
  algorithms/
    baseline.py         Deterministic time-domain and FFT baseline
  providers.py          Gemini and OpenAI-compatible chat adapters
  cli.py                Command-line arguments and command handlers
tests/
  test_tool.py          Unit and CLI tests
```

## Input formats

- CSV with two numeric columns in `I,Q` order. An `I,Q` header is optional.
- NPY containing either a one-dimensional complex array or a real `N x 2` array
  in `I,Q` order.
- Maximum input size: 256 MiB; maximum sample count: 2,000,000.

## Analyze without AI

From PowerShell in the project directory:

```powershell
.\.venv-1\Scripts\python.exe .\main.py analyze .\capture.csv --sample-rate 2000000 --output .\report.json
```

The deterministic baseline reports sample count, SHA-256, I/Q offset, RMS and
peak magnitude, crest factor, spectral entropy, and up to five spectral peaks.
The numerical implementation is isolated in `iqtool/algorithms/baseline.py`;
`iqtool/analysis.py` only loads/validates files and adds provenance to its report.
Numba JIT-compiles the time-domain metric loop; the FFT remains provided by NumPy.
If `--sample-rate` is omitted, peak frequencies are in cycles/sample rather
than Hz. The report is JSON and can be reviewed or extended by other tools.

## Baseline algorithm

For complex samples \(x[n] = I[n] + jQ[n]\), the baseline computes:

- I/Q means: \(\bar I = \frac{1}{N}\sum I[n]\), \(\bar Q = \frac{1}{N}\sum Q[n]\).
- RMS magnitude: \(\sqrt{\frac{1}{N}\sum |x[n]|^2}\); peak magnitude is
  \(\max |x[n]|\), and crest factor is peak divided by RMS (or zero for silence).
- A mean-removed, centered FFT: \(X[k] = FFT(x[n] - \bar x)\). The reported
  spectral peaks are the five strongest local maxima of \(|X[k]|^2\).
- Relative peak power: \(|X[k]|^2 / \sum_k |X[k]|^2\).
- Spectral entropy: \(-\sum_k p[k]\log_2 p[k]\), where \(p[k]\) is each
  non-zero FFT bin's fraction of total power.

Samples are normalized by their largest magnitude before calculation to reduce
overflow risk; this does not change frequency locations or relative spectral
power. Frequency bins are spaced by `sample_rate / sample_count` when the sample
rate is supplied. No window is applied and peaks are not interpolated, so
off-bin tones can spread energy across bins and estimates are limited by the
capture duration. The metrics characterize the supplied capture; they do not
classify anomalies or prove vulnerabilities.

## Optional AI chat

Gemini is the default provider. Set its API key in the process environment;
the program does not save it:

```powershell
$env:GEMINI_API_KEY = "your-key"
.\.venv-1\Scripts\python.exe .\main.py chat .\report.json
```

Pass `--model MODEL_NAME` to choose a Gemini model. OpenAI-compatible endpoints
can also be used by specifying their base URL, model, and optional key:

```powershell
$env:OPENAI_COMPATIBLE_BASE_URL = "http://localhost:1234/v1"
$env:OPENAI_COMPATIBLE_API_KEY = "your-key"
.\.venv-1\Scripts\python.exe .\main.py chat .\report.json --provider openai-compatible --model MODEL_NAME
```

Only summary measurements from the report are sent; the original IQ file is
not uploaded. Proprietary APIs that are not OpenAI-compatible need a provider
adapter added by the user.

## Limits

IQ analysis can identify measurable signal properties, not establish a
vulnerability, infer a quantum state, or prove a security impact. Compare
captures against a known-good reference and record instrument calibration,
sampling configuration, and test authorization before drawing conclusions.

Run the local tests with:

```powershell
.\.venv-1\Scripts\python.exe -m unittest
```
