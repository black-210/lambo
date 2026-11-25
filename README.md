# IQ Research Workbench

An offline-first workbench for authorized IQ recordings, local evidence integrity,
generic physical measurement traces, read-only source checks, and educational
single-qubit simulation. Start it without arguments for a guided menu:

```powershell
.\.venv-1\Scripts\python.exe .\main.py
```

The optional AI chat explains saved reports. Reports contain measurements and
findings only; AI does not prove a vulnerability or replace expert review.

## Project layout

```text
main.py                 CLI entry point
iqtool/
  analysis.py           IQ file loading, validation, and report provenance
  algorithms/
    baseline.py         Deterministic time-domain and FFT baseline
  audit.py              Read-only local source pattern checks
  forensics.py          SHA-256 evidence inventory and verification
  physical.py           Robust statistics for measurement traces
  providers.py          Gemini and OpenAI-compatible chat adapters
  cli.py                Command-line arguments and command handlers
  quantum.py            Idealized single-qubit state-vector simulation
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

Only selected summary fields and up to 20 findings/observations are sent; source
contents, evidence file contents, and original signal captures are not uploaded.
Proprietary APIs that are not OpenAI-compatible need a provider adapter added
by the user.

## Other workbench tools

Create a SHA-256 inventory, then verify the evidence against it later. Save the
manifest outside the evidence directory so it is not counted as evidence:

```powershell
.\.venv-1\Scripts\python.exe .\main.py forensic inventory .\evidence --output .\evidence-manifest.json
.\.venv-1\Scripts\python.exe .\main.py forensic verify .\evidence .\evidence-manifest.json
```

The inventory skips `.git`, virtual environments, and Python caches. It records
relative paths, byte sizes, and hashes; it does not establish authenticity or a
legal chain of custody.

Analyze a one-column measurement CSV or a `time,measurement` CSV. A reference is
optional and only aggregate statistics are compared:

```powershell
.\.venv-1\Scripts\python.exe .\main.py physical .\trace.csv --reference .\reference.csv
```

Run read-only, local source-pattern checks (the code is never executed):

```powershell
.\.venv-1\Scripts\python.exe .\main.py audit .\source
```

The small static scanner flags a few common risky patterns for manual review; it
is not a complete vulnerability scanner and can report false positives.

Simulate an idealized qubit initialized in \(|0\rangle\), apply gates, and read
the basis-state probabilities:

```powershell
.\.venv-1\Scripts\python.exe .\main.py quantum --gates H,X
```

Supported gates are `H`, `X`, `Y`, `Z`, `S`, and `T`. Optional `--theta` and
`--phi` set the initial state angles in radians.

## Limits

These tools operate on local files and do not transmit RF, interact with devices,
contact remote targets, execute scanned code, extract secrets, or test
exploitability. Statistical deviations, static findings, and idealized quantum
outputs are indicators for further authorized expert review—not proof of a
physical, security, or quantum-mechanical vulnerability. Record instrument
calibration, measurement conditions, and authorization before drawing conclusions.

Run the local tests with:

```powershell
.\.venv-1\Scripts\python.exe -m unittest
```
