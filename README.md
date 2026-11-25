# IQ Hardware Red-Team & Research Workbench

A Rust, offline-first, authorized workbench for hardware security red-team assessments, IQ signal anomaly screening, physical measurement trace analysis, evidence integrity verification, static hardware/firmware review, and educational single-qubit simulation.

## Key Capabilities

- **IQ RF/Physical Anomaly Screening (`signal.rs`)**: Supports `.csv`, `.npy`, and raw SDR binary IQ captures (`.cf32`, `.cs8`, `.cu8`). Applies Hann windowing prior to FFT, computes I/Q gain imbalance, quadrature phase skew, DC offset / LO leakage ratio, SNR, Spurious-Free Dynamic Range (SFDR), Occupied Bandwidth (99% OBW), spectral flatness, signal-character indicators, transient burst detection, and a time-frequency spectrogram.
- **Physical Trace Side-Channel Screening (`physical.rs`)**: MAD-based glitch/outlier extraction, FFT clock-harmonic periodicity ratio, lag autocorrelation peak, step-change/drift detection, higher-order moments (skewness, excess kurtosis), and reference trace comparison with Welch's t-statistic screening.
- **Hardware & Firmware Static Audit (`audit.rs`)**: Read-only local scanner covering C/C++, Rust, Python, JS/TS, HDL (`.v`, `.sv`, `.vhd`), DeviceTree (`.dts`), and board configs for JTAG/SWD unlock flags, UART debug consoles, secure-boot bypasses, disabled watchdog/brownout, unsafe memory APIs, weak PRNG/crypto, disabled TLS verification, PEM private keys, and hardcoded secrets. Exports **SARIF v2.1.0**.
- **Legal Authorization & Tamper-Evident Audit Ledger (`legal.rs`)**: Scope attestation (`scope.json`, enforcing `offline_only: true`) and a SHA-256 hash-chained audit ledger (`audit_ledger.jsonl`).
- **Unified Assessment & Report Exports (`assess.rs`)**: Combines IQ, physical traces, and firmware audits into a single risk-scored JSON, standalone HTML, Markdown, and SARIF report.
- **Easy Rust Library API (`lib.rs`)**: Ergonomic `Workbench` builder and `prelude` module.
- **CLI & Bilingual GUI (`main.rs`, `gui.rs`)**: Full `clap` CLI plus a local localhost-only (`127.0.0.1`) Arabic/English interactive web dashboard with Canvas visualizations (IQ Constellation, FFT Spectrum, Envelope, RF Spectrogram/Waterfall, Physical Waveform & Spectrum).

## Quick Start

Run lints and tests:

```powershell
cargo clippy --all-targets -- -D warnings
cargo test
```

Launch the Graphical Workbench (GUI):

```powershell
cargo run -- gui
```

Generate synthetic legal lab demo data and run a full assessment:

```powershell
cargo run -- sample --output-dir .\demo_lab
cargo run -- assess `
  --scope .\demo_lab\scope.json `
  --iq .\demo_lab\iq_capture_demo.csv --sample-rate 2000000 `
  --physical .\demo_lab\physical_trace_demo.csv --reference .\demo_lab\physical_reference_demo.csv `
  --source .\demo_lab\sample_firmware `
  --ledger .\demo_lab\audit_ledger.jsonl `
  --html .\demo_lab\report.html `
  --markdown .\demo_lab\report.md `
  --sarif .\demo_lab\report.sarif `
  --output .\demo_lab\report.json
cargo run -- ledger .\demo_lab\audit_ledger.jsonl
```

## Legal & Safety Boundaries

All tools operate strictly on **authorized local files**. They do not transmit RF, jam signals, interact with live hardware devices, contact external targets, execute scanned code, extract cryptographic keys, or test exploitability. Findings and statistical anomaly scores are indicators for authorized expert review—not proof of vulnerability.
