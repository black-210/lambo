use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use iq_research_workbench::ai::{autonomous_workspace_audit, diagnose_report_offline, start_chat};
use iq_research_workbench::cryptanalysis::{
    aes_ctr_reuse, berlekamp_massey_gf2, crib_drag, detect_ecb_blocks, entropy_score,
    frequency_analysis, lll_reduce, lll_subset_sum_audit, nist_randomness_suite, rsa_audit,
    rsa_batch_gcd, rsa_common_modulus_check, vigenere_crack, xor_key_recovery,
};
use iq_research_workbench::hardware::{
    decode_i2c_vcd, decode_spi_vcd, decode_uart_vcd, discover_local_hardware,
};
use iq_research_workbench::physical::analyze_trace_matrix;
use iq_research_workbench::protocol::analyze_protocol_capture;
use iq_research_workbench::quantum::{simulate_bb84, simulate_circuit, simulate_qubit};
use iq_research_workbench::{
    AssessmentInput, analyze_iq, analyze_trace, assess_engagement, audit_to_sarif,
    create_manifest, create_scope_file, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace, inspect_firmware_binary, launch_gui,
    scan_source_tree, verify_audit_ledger, verify_manifest, verify_scope_file,
};
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use crate::attack::AttackAnalyzer;
pub mod attack;
#[derive(Parser)]
#[command(
    name = "iq-workbench",
    version,
    about = "Authorized offline hardware red-team, RF IQ, side-channel, hardware bus, cryptanalysis, autonomous AI, and forensics workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an IQ capture (.csv, .npy, .cf32, .cs16, .cs8, .cu8, .wav, .sigmf-meta)
    Analyze {
        iq_file: PathBuf,
        #[arg(long)]
        sample_rate: Option<f64>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Screen a physical trace (.csv) or multi-trace side-channel matrix (--matrix)
    Physical {
        trace: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long, default_value_t = 6.0)]
        threshold: f64,
        /// Treat input CSV as a multi-trace labeled matrix (`label,s0,s1,...`) for TVLA/NICV/SNR
        #[arg(long)]
        matrix: bool,
        /// Cross-correlation jitter alignment half-window (samples) when --matrix is set
        #[arg(long, default_value_t = 0)]
        align_window: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Create or verify a SHA-256 evidence manifest
    Forensic {
        #[command(subcommand)]
        command: ForensicCommand,
    },
    /// Static read-only scan of hardware/firmware configs and source code
    Audit {
        root: PathBuf,
        #[arg(long)]
        sarif: Option<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Manage legal authorization scope files
    Scope {
        #[command(subcommand)]
        command: ScopeCommand,
    },
    /// Run a unified hardware red-team assessment across IQ, physical trace, and source code
    Assess(Box<AssessArgs>),
    /// Verify a tamper-evident SHA-256 audit ledger (.jsonl)
    Ledger { ledger: PathBuf },
    /// Generate legal synthetic lab demo files for testing CLI & GUI
    Sample {
        #[arg(long, default_value = "./demo_lab")]
        output_dir: PathBuf,
    },
    /// Launch the local browser-based graphical workbench (bound strictly to 127.0.0.1)
    Gui {
        #[arg(long, default_value_t = 8420)]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Quantum simulator (single-qubit, multi-qubit circuits with --qubits, or --bb84)
    Quantum {
        #[arg(long, default_value = "")]
        gates: String,
        #[arg(long, default_value_t = 0.0)]
        theta: f64,
        #[arg(long, default_value_t = 0.0)]
        phi: f64,
        /// Number of qubits for multi-qubit circuit mode (e.g. --qubits 2 --gates "H 0,CNOT 0 1")
        #[arg(long)]
        qubits: Option<usize>,
        /// Run BB84 QBER channel eavesdropper simulation with N photons
        #[arg(long)]
        bb84_photons: Option<usize>,
        #[arg(long, default_value_t = 0.0)]
        eve_ratio: f64,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Offline binary firmware surface & ELF hardening inspector
    Firmware {
        firmware: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Discuss a saved JSON report (`--provider offline|gemini|openai-compatible`)
    Chat(ChatArgs),
    /// Cryptanalysis & cryptographic weakness auditing (from-scratch BigUint, LLL, NIST, LFSR)
    Crypto {
        #[command(subcommand)]
        command: CryptoCommand,
    },
    /// Passive hardware interface discovery & VCD logic-analyzer bus decoders (UART, SPI, I2C)
    Hardware {
        #[command(subcommand)]
        command: HardwareCommand,
    },
    /// Offline protocol capture analyzer (.pcap binary or .csv)
    Protocol {
        capture: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Autonomous Physical & Hardware Security AI Engine (offline auto-discovery & correlation)
    Ai {
        #[command(subcommand)]
        command: AiCommand,
    },
}

#[derive(Subcommand)]
enum CryptoCommand {
    /// Multi-stage RSA public-key weakness audit (arbitrary-precision Fermat, p-1, Rho, Wiener)
    RsaAudit {
        #[arg(long)]
        modulus: String,
        #[arg(long, default_value = "65537")]
        exponent: String,
        #[arg(long, default_value_t = 50000)]
        max_steps: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Audit multiple RSA moduli (comma-separated or file lines) for shared primes (Batch GCD)
    BatchGcd {
        #[arg(long, num_args = 2..)]
        moduli: Vec<String>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Check common-modulus vulnerability across (N, e1, e2)
    CommonModulus {
        #[arg(long)]
        modulus: String,
        #[arg(long)]
        e1: String,
        #[arg(long)]
        e2: String,
        #[arg(long)]
        c1: Option<String>,
        #[arg(long)]
        c2: Option<String>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// LLL Lattice Basis Reduction from JSON 2D array (e.g. '[[1,127],[0,3233]]')
    Lll {
        #[arg(long)]
        basis_json: String,
        #[arg(long, default_value_t = 0.99)]
        delta: f64,
        #[command(flatten)]
        output: OutputArg,
    },
    /// LLL low-density subset-sum / knapsack audit
    LllSubset {
        #[arg(long, value_delimiter = ',')]
        weights: Vec<i64>,
        #[arg(long)]
        target: i64,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Berlekamp-Massey GF(2) minimal LFSR linear complexity analyzer
    Lfsr {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// NIST SP 800-22 Statistical Randomness Suite (5 tests with real p-values)
    Nist {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Detect deterministic AES/DES ECB repeated ciphertext blocks
    Ecb {
        file: PathBuf,
        #[arg(long, default_value_t = 16)]
        block_size: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Detect AES-CTR keystream reuse via pairwise XOR
    AesCtr {
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        key: String,
        #[arg(long, num_args = 2..)]
        ciphertexts: Vec<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Slide a known plaintext crib across XOR of two reused-keystream files
    CribDrag {
        file1: PathBuf,
        file2: PathBuf,
        #[arg(long)]
        crib: String,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Byte frequency & Index of Coincidence analysis
    Freq {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Shannon entropy score
    Entropy {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Vigenère Kasiski + IC + chi-squared crack
    Vigenere {
        file: PathBuf,
        #[arg(long, default_value_t = 20)]
        max_key_len: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Repeating-key XOR key recovery (`--key-len 0` auto-estimates via Hamming distance)
    Xor {
        file: PathBuf,
        #[arg(long, default_value_t = 0)]
        key_len: usize,
        #[command(flatten)]
        output: OutputArg,
    },
}

#[derive(Subcommand)]
enum HardwareCommand {
    /// Passive read-only OS discovery of attached serial COM ports & USB SDR/logic/debug interfaces
    Discover {
        #[command(flatten)]
        output: OutputArg,
    },
    /// Decode UART 8N1 serial traffic from a .vcd logic analyzer trace (auto-baud if omitted)
    Uart {
        vcd: PathBuf,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long)]
        baud: Option<f64>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Decode synchronous SPI bus transactions from a .vcd trace
    Spi {
        vcd: PathBuf,
        #[arg(long)]
        sclk: Option<String>,
        #[arg(long)]
        mosi: Option<String>,
        #[arg(long)]
        miso: Option<String>,
        #[arg(long)]
        cs: Option<String>,
        #[arg(long, default_value_t = 0)]
        cpol: u8,
        #[arg(long, default_value_t = 0)]
        cpha: u8,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Decode I2C START/STOP/Address/ACK/Data transactions from a .vcd trace
    I2c {
        vcd: PathBuf,
        #[arg(long)]
        scl: Option<String>,
        #[arg(long)]
        sda: Option<String>,
        #[command(flatten)]
        output: OutputArg,
    },
}

#[derive(Subcommand)]
enum AiCommand {
    /// Autonomously discover & test all artifacts in a workspace and generate correlated AI report
    Audit {
        workspace: PathBuf,
        #[arg(long)]
        scope: Option<PathBuf>,
        #[arg(long)]
        ledger: Option<PathBuf>,
        #[arg(long)]
        sample_rate: Option<f64>,
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        markdown: Option<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Run offline bilingual diagnostic interpreter on a saved JSON report
    Diagnose {
        report: PathBuf,
        #[arg(long)]
        question: Option<String>,
        #[arg(long, default_value = "ar")]
        lang: String,
    },
}

#[derive(Args)]
struct OutputArg {
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ForensicCommand {
    Inventory {
        root: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    Verify {
        root: PathBuf,
        manifest: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
}

#[derive(Subcommand)]
enum ScopeCommand {
    Init {
        path: PathBuf,
        #[arg(long, default_value = "ENG-2026-001")]
        engagement_id: String,
        #[arg(long, default_value = "authorized-analyst")]
        operator: String,
    },
    Verify { path: PathBuf },
}

#[derive(Args)]
struct AssessArgs {
    #[arg(long)]
    iq: Option<PathBuf>,
    #[arg(long)]
    sample_rate: Option<f64>,
    #[arg(long)]
    physical: Option<PathBuf>,
    #[arg(long)]
    reference: Option<PathBuf>,
    #[arg(long, default_value_t = 6.0)]
    threshold: f64,
    #[arg(long)]
    source: Option<PathBuf>,
    #[arg(long)]
    scope: Option<PathBuf>,
    #[arg(long)]
    ledger: Option<PathBuf>,
    #[arg(long)]
    html: Option<PathBuf>,
    #[arg(long)]
    markdown: Option<PathBuf>,
    #[arg(long)]
    sarif: Option<PathBuf>,
    #[command(flatten)]
    output: OutputArg,
}

#[derive(Args)]
struct ChatArgs {
    report: PathBuf,
    #[arg(long, default_value = "offline")]
    provider: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

fn absolute_path(path: &Path) -> PathBuf {
    path.canonicalize()
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(path))
}

fn ensure_output_distinct(output: &Option<PathBuf>, inputs: &[&Path]) -> Result<()> {
    if let Some(output) = output {
        let output = absolute_path(output);
        if inputs.iter().any(|input| output == absolute_path(input)) {
            bail!("Report output must not overwrite an input file.");
        }
    }
    Ok(())
}

fn ensure_output_outside(output: &Option<PathBuf>, root: &Path) -> Result<()> {
    if output
        .as_ref()
        .is_some_and(|output| absolute_path(output).starts_with(absolute_path(root)))
    {
        bail!("Save the report outside the scanned/evidence directory.");
    }
    Ok(())
}

fn write_report(report: Value, output: Option<&Path>) -> Result<()> {
    let rendered = serde_json::to_string_pretty(&report)?;
    if let Some(output) = output {
        std::fs::write(output, format!("{rendered}\n"))
            .with_context(|| format!("Writing report to {}", output.display()))?;
        println!("Report written to {}", output.display());
    } else {
        println!("{rendered}");
    }
    Ok(())
}

fn read_report(path: &Path) -> Result<Value> {
    let report: Value = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("Reading report {}", path.display()))?,
    )
    .context("Could not read a valid report JSON.")?;
    if !report.get("metrics").is_some_and(Value::is_object) && report.get("analysis").is_none() {
        bail!("Report JSON must contain a metrics object or an analysis field.");
    }
    Ok(report)
}

fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Analyze {
            iq_file,
            sample_rate,
            output,
        } => {
            ensure_output_distinct(&output.output, &[&iq_file])?;
            write_report(analyze_iq(&iq_file, sample_rate)?, output.output.as_deref())
        }
        Command::Physical {
            trace,
            reference,
            threshold,
            matrix,
            align_window,
            output,
        } => {
            let mut inputs = vec![trace.as_path()];
            if let Some(reference) = reference.as_deref() {
                inputs.push(reference);
            }
            ensure_output_distinct(&output.output, &inputs)?;
            let rep = if matrix {
                analyze_trace_matrix(&trace, align_window)?
            } else {
                analyze_trace(&trace, reference.as_deref(), threshold)?
            };
            write_report(rep, output.output.as_deref())
        }
        Command::Forensic { command } => match command {
            ForensicCommand::Inventory { root, output } => {
                ensure_output_outside(&output.output, &root)?;
                write_report(create_manifest(&root)?, output.output.as_deref())
            }
            ForensicCommand::Verify {
                root,
                manifest,
                output,
            } => {
                ensure_output_distinct(&output.output, &[&manifest])?;
                ensure_output_outside(&output.output, &root)?;
                if absolute_path(&manifest).starts_with(absolute_path(&root)) {
                    bail!("Keep the evidence manifest outside the evidence directory.");
                }
                write_report(verify_manifest(&root, &manifest)?, output.output.as_deref())
            }
        },
        Command::Audit {
            root,
            sarif,
            output,
        } => {
            ensure_output_outside(&output.output, &root)?;
            ensure_output_outside(&sarif, &root)?;
            let report = scan_source_tree(&root)?;
            if let Some(sarif_path) = sarif.as_deref() {
                let sarif_doc = audit_to_sarif(&report)?;
                std::fs::write(
                    sarif_path,
                    format!("{}\n", serde_json::to_string_pretty(&sarif_doc)?),
                )?;
                println!("SARIF report written to {}", sarif_path.display());
            }
            write_report(report, output.output.as_deref())
        }
        Command::Scope { command } => match command {
            ScopeCommand::Init {
                path,
                engagement_id,
                operator,
            } => write_report(create_scope_file(&path, &engagement_id, &operator)?, None),
            ScopeCommand::Verify { path } => write_report(verify_scope_file(&path)?, None),
        },
        Command::Assess(args) => {
            let report = assess_engagement(&AssessmentInput {
                iq_file: args.iq,
                sample_rate_hz: args.sample_rate,
                physical_trace: args.physical,
                physical_reference: args.reference,
                physical_threshold: args.threshold,
                source_dir: args.source,
                scope_file: args.scope,
                ledger_file: args.ledger,
            })?;
            if let Some(html_path) = args.html.as_deref() {
                export_html_report(&report, html_path)?;
                println!("HTML report written to {}", html_path.display());
            }
            if let Some(md_path) = args.markdown.as_deref() {
                export_markdown_report(&report, md_path)?;
                println!("Markdown report written to {}", md_path.display());
            }
            if let Some(sarif_path) = args.sarif.as_deref() {
                export_sarif_report(&report, sarif_path)?;
                println!("SARIF report written to {}", sarif_path.display());
            }
            write_report(report, args.output.output.as_deref())
        }
        Command::Ledger { ledger } => write_report(verify_audit_ledger(&ledger)?, None),
        Command::Sample { output_dir } => {
            write_report(generate_demo_workspace(&output_dir)?, None)
        }
        Command::Gui { port, no_open } => launch_gui(port, !no_open),
        Command::Quantum {
            gates,
            theta,
            phi,
            qubits,
            bb84_photons,
            eve_ratio,
            output,
        } => {
            let rep = if let Some(photons) = bb84_photons {
                simulate_bb84(photons, eve_ratio)?
            } else if let Some(nq) = qubits {
                let ops: Vec<String> = gates
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                simulate_circuit(nq, &ops)?
            } else {
                let g: Vec<String> = gates
                    .split(',')
                    .map(str::trim)
                    .filter(|gate| !gate.is_empty())
                    .map(str::to_owned)
                    .collect();
                simulate_qubit(&g, theta, phi)?
            };
            write_report(rep, output.output.as_deref())
        }
        Command::Chat(args) => {
            let report = read_report(&args.report)?;
            start_chat(
                &report,
                &args.provider,
                args.model.as_deref(),
                args.base_url.as_deref(),
            )
        }
        Command::Firmware { firmware, output } => {
            write_report(inspect_firmware_binary(&firmware)?, output.output.as_deref())
        }
        Command::Crypto { command } => match command {
            CryptoCommand::RsaAudit {
                modulus,
                exponent,
                max_steps,
                output,
            } => write_report(
                rsa_audit(&exponent, &modulus, max_steps)?,
                output.output.as_deref(),
            ),
            CryptoCommand::BatchGcd { moduli, output } => {
                write_report(rsa_batch_gcd(&moduli)?, output.output.as_deref())
            }
            CryptoCommand::CommonModulus {
                modulus,
                e1,
                e2,
                c1,
                c2,
                output,
            } => write_report(
                rsa_common_modulus_check(&modulus, &e1, &e2, c1.as_deref(), c2.as_deref())?,
                output.output.as_deref(),
            ),
            CryptoCommand::Lll {
                basis_json,
                delta,
                output,
            } => {
                let basis: Vec<Vec<f64>> =
                    serde_json::from_str(&basis_json).context("Parsing basis JSON 2D array")?;
                write_report(lll_reduce(&basis, delta)?, output.output.as_deref())
            }
            CryptoCommand::LllSubset {
                weights,
                target,
                output,
            } => write_report(
                lll_subset_sum_audit(&weights, target)?,
                output.output.as_deref(),
            ),
            CryptoCommand::Lfsr { file, output } => {
                let data = std::fs::read(&file)?;
                write_report(berlekamp_massey_gf2(&data)?, output.output.as_deref())
            }
            CryptoCommand::Nist { file, output } => {
                let data = std::fs::read(&file)?;
                write_report(nist_randomness_suite(&data)?, output.output.as_deref())
            }
            CryptoCommand::Ecb {
                file,
                block_size,
                output,
            } => {
                let data = std::fs::read(&file)?;
                write_report(detect_ecb_blocks(&data, block_size)?, output.output.as_deref())
            }
            CryptoCommand::AesCtr {
                nonce,
                key,
                ciphertexts,
                output,
            } => {
                let mut cts = Vec::new();
                for p in &ciphertexts {
                    cts.push(std::fs::read(p)?);
                }
                write_report(aes_ctr_reuse(&nonce, &key, &cts)?, output.output.as_deref())
            }
            CryptoCommand::CribDrag {
                file1,
                file2,
                crib,
                output,
            } => {
                let c1 = std::fs::read(&file1)?;
                let c2 = std::fs::read(&file2)?;
                write_report(
                    crib_drag(&c1, &c2, crib.as_bytes())?,
                    output.output.as_deref(),
                )
            }
            CryptoCommand::Freq { file, output } => {
                let data = std::fs::read(&file)?;
                write_report(frequency_analysis(&data)?, output.output.as_deref())
            }
            CryptoCommand::Entropy { file, output } => {
                let data = std::fs::read(&file)?;
                write_report(entropy_score(&data)?, output.output.as_deref())
            }
            CryptoCommand::Vigenere {
                file,
                max_key_len,
                output,
            } => {
                let data = std::fs::read(&file)?;
                write_report(vigenere_crack(&data, max_key_len)?, output.output.as_deref())
            }
            CryptoCommand::Xor {
                file,
                key_len,
                output,
            } => {
                let data = std::fs::read(&file)?;
                write_report(xor_key_recovery(&data, key_len)?, output.output.as_deref())
            }
        },
        Command::Hardware { command } => match command {
            HardwareCommand::Discover { output } => {
                write_report(discover_local_hardware()?, output.output.as_deref())
            }
            HardwareCommand::Uart {
                vcd,
                channel,
                baud,
                output,
            } => write_report(
                decode_uart_vcd(&vcd, channel.as_deref(), baud)?,
                output.output.as_deref(),
            ),
            HardwareCommand::Spi {
                vcd,
                sclk,
                mosi,
                miso,
                cs,
                cpol,
                cpha,
                output,
            } => write_report(
                decode_spi_vcd(
                    &vcd,
                    sclk.as_deref(),
                    mosi.as_deref(),
                    miso.as_deref(),
                    cs.as_deref(),
                    cpol,
                    cpha,
                )?,
                output.output.as_deref(),
            ),
            HardwareCommand::I2c {
                vcd,
                scl,
                sda,
                output,
            } => write_report(
                decode_i2c_vcd(&vcd, scl.as_deref(), sda.as_deref())?,
                output.output.as_deref(),
            ),
        },
        Command::Protocol { capture, output } => write_report(
            analyze_protocol_capture(&capture)?,
            output.output.as_deref(),
        ),
        Command::Ai { command } => match command {
            AiCommand::Audit {
                workspace,
                scope,
                ledger,
                sample_rate,
                html,
                markdown,
                output,
            } => {
                let rep = autonomous_workspace_audit(
                    &workspace,
                    scope.as_deref(),
                    ledger.as_deref(),
                    sample_rate,
                )?;
                if let Some(hp) = html.as_deref() {
                    export_html_report(&rep, hp)?;
                    println!("HTML report written to {}", hp.display());
                }
                if let Some(mp) = markdown.as_deref() {
                    export_markdown_report(&rep, mp)?;
                    println!("Markdown report written to {}", mp.display());
                }
                write_report(rep, output.output.as_deref())
            }
            AiCommand::Diagnose {
                report,
                question,
                lang,
            } => {
                let rep = read_report(&report)?;
                write_report(
                    diagnose_report_offline(&rep, question.as_deref(), &lang),
                    None,
                )
            }
        },
    }
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().to_owned())
}

fn menu() -> Result<()> {
    loop {
        println!(
            "\nIQ Hardware Red-Team Workbench (Authorized Offline Mode)\n\
             1) IQ capture analysis (.csv/.npy/.cf32/.cs16/.cs8/.cu8/.wav/.sigmf-meta)\n\
             2) Physical measurement trace & TVLA screening\n\
             3) Create / Verify SHA-256 evidence manifest\n\
             4) Hardware & Firmware static audit + ELF binary review\n\
             5) Autonomous Physical AI workspace scan & report\n\
             6) Cryptanalysis lab (RSA audit, NIST randomness, LLL, LFSR, XOR)\n\
             7) Hardware discovery & VCD bus decoders (UART / SPI / I2C)\n\
             8) Protocol capture analysis (.pcap / .csv)\n\
             9) Quantum multi-qubit / BB84 simulator\n\
             10) Launch Graphical Workbench (GUI)\n\
             11) Generate demo lab dataset\n\
             0) Exit"
        );
        let choice = prompt("Choose: ")?;
        if choice.is_empty() || matches!(choice.as_str(), "0" | "exit" | "quit") {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            match choice.as_str() {
                "1" => {
                    let path = PathBuf::from(prompt("IQ capture path: ")?);
                    let rate = prompt("Sample rate Hz (optional): ")?;
                    dispatch(Command::Analyze {
                        iq_file: path,
                        sample_rate: (!rate.is_empty()).then(|| rate.parse().unwrap_or(1.0)),
                        output: OutputArg { output: None },
                    })
                }
                "2" => {
                    let trace = PathBuf::from(prompt("Trace CSV path: ")?);
                    let matrix = prompt("Is this a multi-trace TVLA matrix? (y/n): ")?;
                    dispatch(Command::Physical {
                        trace,
                        reference: None,
                        threshold: 6.0,
                        matrix: matrix.eq_ignore_ascii_case("y"),
                        align_window: 0,
                        output: OutputArg { output: None },
                    })
                }
                "3" => {
                    let root = PathBuf::from(prompt("Evidence directory: ")?);
                    dispatch(Command::Forensic {
                        command: ForensicCommand::Inventory {
                            root,
                            output: OutputArg { output: None },
                        },
                    })
                }
                "4" => dispatch(Command::Audit {
                    root: PathBuf::from(prompt("Source directory: ")?),
                    sarif: None,
                    output: OutputArg { output: None },
                }),
                "5" => dispatch(Command::Ai {
                    command: AiCommand::Audit {
                        workspace: PathBuf::from(prompt("Workspace directory [./demo_lab]: ")?),
                        scope: None,
                        ledger: None,
                        sample_rate: Some(2_000_000.0),
                        html: None,
                        markdown: None,
                        output: OutputArg { output: None },
                    },
                }),
                "6" => {
                    let n = prompt("RSA Modulus N (dec or 0x...): ")?;
                    let e = prompt("Exponent e [65537]: ")?;
                    dispatch(Command::Crypto {
                        command: CryptoCommand::RsaAudit {
                            modulus: n,
                            exponent: if e.is_empty() { "65537".into() } else { e },
                            max_steps: 50_000,
                            output: OutputArg { output: None },
                        },
                    })
                }
                "7" => dispatch(Command::Hardware {
                    command: HardwareCommand::Discover {
                        output: OutputArg { output: None },
                    },
                }),
                "8" => dispatch(Command::Protocol {
                    capture: PathBuf::from(prompt("PCAP or CSV path: ")?),
                    output: OutputArg { output: None },
                }),
                "9" => dispatch(Command::Quantum {
                    gates: prompt("Gates (e.g. H,T or 'H 0,CNOT 0 1'): ")?,
                    theta: 0.0,
                    phi: 0.0,
                    qubits: None,
                    bb84_photons: None,
                    eve_ratio: 0.0,
                    output: OutputArg { output: None },
                }),
                "10" => dispatch(Command::Gui {
                    port: 8420,
                    no_open: false,
                }),
                "11" => dispatch(Command::Sample {
                    output_dir: PathBuf::from("./demo_lab"),
                }),
                _ => {
                    println!("Choose one of the listed options.");
                    Ok(())
                }
            }
        })();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
        }
    }
}

fn run() -> Result<()> {
    if std::env::args_os().len() == 1 {
        return menu();
    }
    let cli = Cli::parse();
    dispatch(cli.command)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(2);
    }
}
