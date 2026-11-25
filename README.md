# IQ Research Workbench

A Rust, offline-first workbench for authorized IQ recordings, local evidence
integrity, physical measurement traces, read-only source checks, and educational
single-qubit simulation. The modules are separated by task under `src/` so each
algorithm can be understood and extended independently.

## Get started

Install the stable Rust toolchain, then run the guided menu:

```powershell
cargo run
```

Build an optimized executable with:

```powershell
cargo build --release
```

Run the test suite with:

```powershell
cargo test
```

## Commands

Analyze a CSV containing `I,Q` columns, or a numeric NPY file containing a 1D
complex array or a 2D real array with I,Q columns:

```powershell
cargo run -- analyze .\capture.csv --sample-rate 2000000 --output .\report.json
```

Screen a one-column physical measurement CSV, or a `time,measurement` CSV.
Optionally compare aggregate measurements with a reference:

```powershell
cargo run -- physical .\trace.csv --reference .\reference.csv
```

Create and later verify a SHA-256 evidence inventory. Keep the manifest outside
the evidence directory:

```powershell
cargo run -- forensic inventory .\evidence --output .\evidence-manifest.json
cargo run -- forensic verify .\evidence .\evidence-manifest.json
```

Run read-only static source checks on a local directory:

```powershell
cargo run -- audit .\source
```

Simulate an idealized qubit initialized in \(|0\rangle\):

```powershell
cargo run -- quantum --gates H,X
```

Supported gates are `H`, `X`, `Y`, `Z`, `S`, and `T`. Optional `--theta` and
`--phi` arguments set the initial-state angles in radians.

Discuss a saved JSON report with an optional AI provider:

```powershell
$env:GEMINI_API_KEY = "your-key"
cargo run -- chat .\report.json
```

OpenAI-compatible endpoints can be selected with `--provider openai-compatible`,
`--model MODEL_NAME`, and `--base-url URL`. The URL and optional key can also be
provided through `OPENAI_COMPATIBLE_BASE_URL` and `OPENAI_COMPATIBLE_API_KEY`.
Only selected summary fields and up to 20 findings or observations are sent to
the model; source contents, evidence file contents, and original signal captures
are not uploaded.

## Project layout

```text
src/
  main.rs       CLI, report output, and guided menu
  signal.rs     IQ loading, validation, FFT metrics, and provenance
  physical.rs   Robust statistics for measurement traces
  evidence.rs   SHA-256 evidence inventory and verification
  audit.rs      Read-only local source pattern checks
  quantum.rs    Idealized single-qubit state-vector simulation
  ai.rs         Optional report-summary chat adapters
```

## Limits

All tools operate on local files. They do not transmit RF, interact with devices,
contact remote targets, execute scanned code, extract secrets, or test
exploitability. Statistical deviations, static findings, and idealized quantum
outputs are indicators for further authorized expert review—not proof of a
physical, security, or quantum-mechanical vulnerability. Evidence hashes do not
establish authenticity or a legal chain of custody. Record instrument
calibration, measurement conditions, and authorization before drawing conclusions.
