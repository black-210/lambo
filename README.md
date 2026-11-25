# IQ Hardware Red-Team, Cryptanalysis & Physical AI Workbench

An offline-first, authorized Rust platform (**CLI + Local Web GUI + Ergonomic Rust Library**) for hardware security assessments, RF IQ anomaly screening, physical side-channel evaluation, logic-bus decoding, binary protocol inspection, firmware metadata triage, from-scratch cryptographic weakness auditing, and autonomous offline workspace analysis.

## Architecture & Modules

- **IQ / SDR DSP (`src/signal.rs`)**: Supports `.csv`, `.npy`, `.cf32`, `.cs16`, `.cs8`, `.cu8`, `.wav` (RIFF I/Q), and `.sigmf-meta` + `.sigmf-data`. Applies Hann windowing, Welch PSD, CA-CFAR spur extraction, Image Rejection Ratio (IRR), Higher-Order Cumulants Modulation Classification (`C20`, `C40`, `C42`), cyclostationary symbol-rate estimation, transient burst detection, and time-frequency spectrogram.
- **Physical Side-Channel Screening (`src/physical.rs`)**: MAD outlier detection, CUSUM drift/fault alarms, FFT clock-harmonic comb ratio, lag autocorrelation, step-change detection, Welch's t-test TVLA, plus **Multi-Trace Matrix TVLA / NICV / SNR(t)** with cross-correlation jitter alignment.
- **From-Scratch Big-Integer & Cryptanalysis Research (`src/bigint.rs`, `src/cryptanalysis.rs`)**: Zero-dependency arbitrary-precision `BigUint`/`BigInt` arithmetic powering RSA parameter audits (Fermat, Pollard `p-1`, Pollard-Rho Brent, Wiener's continued-fraction small-`d` check, Batch GCD shared-prime check, Common-Modulus check), real **LLL Lattice Basis Reduction** & Subset-Sum auditing, **Berlekamp-Massey GF(2)** minimal LFSR complexity, **NIST SP 800-22** 5-test statistical randomness suite, ECB block repetition detection, CTR/OTP crib-dragging, Vigenère IC/chi-squared recovery, and Hamming-distance XOR recovery.
- **Hardware Discovery & Logic Bus Decoders (`src/hardware.rs`)**: Passive read-only OS enumeration of serial COM ports and USB SDR/logic/debug probes, from-scratch IEEE 1364 `.vcd` logic-analyzer parser, **UART 8N1** (auto-baud), **SPI** (Modes 0–3), and **I2C** decoders, plus the `HardwareCaptureSource` streaming trait for Rust library integration.
- **Protocol Capture Analyzer (`src/protocol.rs`)**: From-scratch binary **`.pcap`** (Ethernet II / IPv4 / TCP / UDP) and **`.csv`** parser flagging cleartext protocols, periodic beaconing CV, port sweeps, DNS exfiltration heuristics, and sensitive payload strings.
- **Firmware & Static Code Audits (`src/firmware.rs`, `src/audit.rs`)**: ELF32/ELF64 defensive binary hardening inspection (`PIE`, `NX`, `RELRO`, stack canary markers), ARM Cortex-M vector-table check, YARA-lite byte patterns, entropy-drop profiling, and SARIF v2.1.0 hardware/code scanner.
- **Autonomous Physical AI & Governance (`src/ai.rs`, `src/legal.rs`, `src/evidence.rs`, `src/assess.rs`)**: Recursive offline workspace audit engine with cross-domain correlation hypotheses, grounded bilingual (`ar`/`en`) offline diagnostic advisor, optional Gemini/OpenAI chat, SHA-256 evidence manifests, legal scope verification, and tamper-evident JSONL hash-chained ledger.
- **Quantum Engine (`src/quantum.rs`)**: Single-qubit and 1..8-qubit universal circuit simulator (`H`, `X`, `Y`, `Z`, `S`, `T`, `RX`, `RY`, `RZ`, `CNOT`, `CZ`, `SWAP`, `TOFFOLI`, `QFT`) plus BB84 QBER eavesdropper simulation.

## Quick Start

```powershell
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- gui
```

Run an autonomous offline AI audit on the generated demo workspace:

```powershell
cargo run -- sample --output-dir .\demo_lab
cargo run -- ai audit .\demo_lab --scope .\demo_lab\scope.json --ledger .\demo_lab\ai_ledger.jsonl --sample-rate 2000000 --output .\demo_lab\ai_report.json
cargo run -- hardware discover
cargo run -- crypto rsa-audit --modulus 90581 --exponent 17993
```

## Legal & Safety Boundaries

All analysis modules operate on **authorized local captures, artifacts, and read-only OS device descriptors**. The tool never transmits RF signals, injects hardware faults, flashes firmware, bypasses hardware protections, or attacks live external targets.
