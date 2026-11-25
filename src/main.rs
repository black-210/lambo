use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use iq_research_workbench::ai::start_chat;
use iq_research_workbench::cryptanalysis::{
    aes_ctr_reuse, coppersmith_stub, entropy_score, frequency_analysis, rsa_factor,
    vigenere_crack, xor_key_recovery,
};
use iq_research_workbench::protocol::analyze_protocol_capture;
use iq_research_workbench::{
    AssessmentInput, analyze_iq, analyze_trace, assess_engagement, audit_to_sarif,
    create_manifest, create_scope_file, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace, inspect_firmware_binary, launch_gui,
    scan_source_tree, simulate_qubit, verify_audit_ledger, verify_manifest, verify_scope_file,
};
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// ─── CLI Definition ──────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "iq-workbench",
    version,
    about = "Authorized offline hardware red-team, IQ, physical trace, cryptanalysis, protocol, and evidence workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an IQ capture (.csv, .npy, .cf32, .cs8, .cu8)
    Analyze {
        iq_file: PathBuf,
        #[arg(long)]
        sample_rate: Option<f64>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Screen a physical measurement trace (.csv)
    Physical {
        trace: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long, default_value_t = 6.0)]
        threshold: f64,
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
    /// Run a unified hardware red-team assessment
    Assess(Box<AssessArgs>),
    /// Verify a tamper-evident SHA-256 audit ledger (.jsonl)
    Ledger { ledger: PathBuf },
    /// Generate synthetic lab demo files
    Sample {
        #[arg(long, default_value = "./demo_lab")]
        output_dir: PathBuf,
    },
    /// Launch the local browser-based GUI (127.0.0.1)
    Gui {
        #[arg(long, default_value_t = 8420)]
        port: u16,
        #[arg(long)]
        no_open: bool,
    },
    /// Educational single-qubit state-vector simulator
    Quantum {
        #[arg(long, default_value = "")]
        gates: String,
        #[arg(long, default_value_t = 0.0)]
        theta: f64,
        #[arg(long, default_value_t = 0.0)]
        phi: f64,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Offline binary firmware surface inspector
    Firmware {
        firmware: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Discuss a saved JSON report with an AI provider
    Chat(ChatArgs),

    // ── NEW ──────────────────────────────────────────────────────────────

    /// Cryptanalysis research utilities (RSA, AES-CTR, Vigenère, XOR, entropy)
    Crypto {
        #[command(subcommand)]
        command: CryptoCommand,
    },
    /// Analyze a protocol capture CSV for anomalies
    Protocol {
        capture: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
}

#[derive(Subcommand)]
enum CryptoCommand {
    /// Factor a small RSA modulus (trial-division + Pollard-Rho)
    Rsa {
        #[arg(long)]
        modulus: u64,
        #[arg(long, default_value_t = 65537)]
        exponent: u64,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Detect AES-CTR keystream reuse
    AesCtr {
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        key: String,
        #[arg(long, num_args = 1..)]
        ciphertexts: Vec<PathBuf>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Frequency analysis on a binary file
    Freq {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Shannon entropy of a binary file
    Entropy {
        file: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Crack a Vigenère cipher (uppercase A-Z text file)
    Vigenere {
        file: PathBuf,
        #[arg(long, default_value_t = 20)]
        max_key_len: usize,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Recover a repeating XOR key
    Xor {
        file: PathBuf,
        #[arg(long)]
        key_len: usize,
        #[command(flatten)]
        output: OutputArg,
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
    #[arg(long, default_value = "gemini")]
    provider: String,
    #[arg(long)]
    model: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
    if !report.get("metrics").is_some_and(Value::is_object) && !report.get("analysis").is_some() {
        bail!("Report JSON must contain a metrics object or an analysis field.");
    }
    Ok(report)
}

// ─── Dispatch ────────────────────────────────────────────────────────────────

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
            output,
        } => {
            let mut inputs = vec![trace.as_path()];
            if let Some(reference) = reference.as_deref() {
                inputs.push(reference);
            }
            ensure_output_distinct(&output.output, &inputs)?;
            write_report(
                analyze_trace(&trace, reference.as_deref(), threshold)?,
                output.output.as_deref(),
            )
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
            output,
        } => {
            let gates: Vec<String> = gates
                .split(',')
                .map(str::trim)
                .filter(|gate| !gate.is_empty())
                .map(str::to_owned)
                .collect();
            write_report(simulate_qubit(&gates, theta, phi)?, output.output.as_deref())
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

        // ── NEW: Cryptanalysis ───────────────────────────────────────────
        Command::Crypto { command } => match command {
            CryptoCommand::Rsa {
                modulus,
                exponent,
                output,
            } => write_report(rsa_factor(exponent, modulus)?, output.output.as_deref()),
            CryptoCommand::AesCtr {
                nonce,
                key,
                ciphertexts,
                output,
            } => {
                let mut cts: Vec<Vec<u8>> = Vec::new();
                for p in &ciphertexts {
                    let data = std::fs::read(p)
                        .with_context(|| format!("reading ciphertext {}", p.display()))?;
                    cts.push(data);
                }
                write_report(aes_ctr_reuse(&nonce, &key, &cts)?, output.output.as_deref())
            }
            CryptoCommand::Freq { file, output } => {
                let data = std::fs::read(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                write_report(frequency_analysis(&data)?, output.output.as_deref())
            }
            CryptoCommand::Entropy { file, output } => {
                let data = std::fs::read(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                write_report(entropy_score(&data)?, output.output.as_deref())
            }
            CryptoCommand::Vigenere {
                file,
                max_key_len,
                output,
            } => {
                let data = std::fs::read(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                write_report(vigenere_crack(&data, max_key_len)?, output.output.as_deref())
            }
            CryptoCommand::Xor {
                file,
                key_len,
                output,
            } => {
                let data = std::fs::read(&file)
                    .with_context(|| format!("reading {}", file.display()))?;
                write_report(xor_key_recovery(&data, key_len)?, output.output.as_deref())
            }
        },

        // ── NEW: Protocol analysis ───────────────────────────────────────
        Command::Protocol { capture, output } => {
            write_report(
                analyze_protocol_capture(&capture)?,
                output.output.as_deref(),
            )
        }
    }
}

// ─── Interactive Menu ────────────────────────────────────────────────────────

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
             1) IQ capture analysis\n\
             2) Physical measurement trace\n\
             3) Create evidence manifest\n\
             4) Verify evidence manifest\n\
             5) Hardware/Firmware source review\n\
             6) Educational qubit simulation\n\
             7) Ask AI about a report\n\
             8) Launch Graphical Workbench (GUI)\n\
             9) Generate demo lab dataset\n\
             10) Cryptanalysis tools\n\
             11) Protocol capture analysis\n\
             0) Exit"
        );
        let choice = prompt("Choose: ")?;
        if choice.is_empty() || matches!(choice.as_str(), "0" | "exit" | "quit") {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            let result = match choice.as_str() {
                "1" => {
                    let path = PathBuf::from(prompt("IQ CSV/NPY/CF32/CS8/CU8 path: ")?);
                    let rate = prompt("Sample rate in Hz (optional): ")?;
                    let rate = if rate.is_empty() {
                        None
                    } else {
                        Some(rate.parse().context("Sample rate must be a number.")?)
                    };
                    dispatch(Command::Analyze {
                        iq_file: path,
                        sample_rate: rate,
                        output: OutputArg { output: None },
                    })
                }
                "2" => {
                    let trace = PathBuf::from(prompt("Measurement CSV path: ")?);
                    let reference = prompt("Reference CSV path (optional): ")?;
                    dispatch(Command::Physical {
                        trace,
                        reference: (!reference.is_empty()).then(|| PathBuf::from(reference)),
                        threshold: 6.0,
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
                "4" => {
                    let root = PathBuf::from(prompt("Evidence directory: ")?);
                    let manifest = PathBuf::from(prompt("Manifest JSON path: ")?);
                    dispatch(Command::Forensic {
                        command: ForensicCommand::Verify {
                            root,
                            manifest,
                            output: OutputArg { output: None },
                        },
                    })
                }
                "5" => dispatch(Command::Audit {
                    root: PathBuf::from(prompt("Local source directory: ")?),
                    sarif: None,
                    output: OutputArg { output: None },
                }),
                "6" => {
                    let gates = prompt("Gates, comma-separated (e.g. H,X): ")?;
                    let theta = prompt("Initial theta in radians [0]: ")?;
                    let phi = prompt("Initial phi in radians [0]: ")?;
                    dispatch(Command::Quantum {
                        gates,
                        theta: if theta.is_empty() {
                            0.0
                        } else {
                            theta.parse().context("Theta must be a number.")?
                        },
                        phi: if phi.is_empty() {
                            0.0
                        } else {
                            phi.parse().context("Phi must be a number.")?
                        },
                        output: OutputArg { output: None },
                    })
                }
                "7" => {
                    let report = PathBuf::from(prompt("Analysis report JSON path: ")?);
                    dispatch(Command::Chat(ChatArgs {
                        report,
                        provider: "gemini".to_owned(),
                        model: None,
                        base_url: None,
                    }))
                }
                "8" => dispatch(Command::Gui {
                    port: 8420,
                    no_open: false,
                }),
                "9" => {
                    let dir = prompt("Demo output directory [./demo_lab]: ")?;
                    dispatch(Command::Sample {
                        output_dir: if dir.is_empty() {
                            PathBuf::from("./demo_lab")
                        } else {
                            PathBuf::from(dir)
                        },
                    })
                }
                "10" => {
                    println!(
                        "\nCryptanalysis Tools:\n\
                         a) RSA factor\n\
                         b) Frequency analysis\n\
                         c) Shannon entropy\n\
                         d) Vigenère crack\n\
                         e) XOR key recovery"
                    );
                    let sub = prompt("Choose (a-e): ")?;
                    match sub.as_str() {
                        "a" => {
                            let n: u64 = prompt("Modulus N: ")?.parse().context("Must be a number")?;
                            let e: u64 = prompt("Public exponent e [65537]: ")?
                                .parse()
                                .unwrap_or(65537);
                            dispatch(Command::Crypto {
                                command: CryptoCommand::Rsa {
                                    modulus: n,
                                    exponent: e,
                                    output: OutputArg { output: None },
                                },
                            })
                        }
                        "b" => {
                            let file = PathBuf::from(prompt("File path: ")?);
                            dispatch(Command::Crypto {
                                command: CryptoCommand::Freq {
                                    file,
                                    output: OutputArg { output: None },
                                },
                            })
                        }
                        "c" => {
                            let file = PathBuf::from(prompt("File path: ")?);
                            dispatch(Command::Crypto {
                                command: CryptoCommand::Entropy {
                                    file,
                                    output: OutputArg { output: None },
                                },
                            })
                        }
                        "d" => {
                            let file = PathBuf::from(prompt("Ciphertext file (uppercase A-Z): ")?);
                            dispatch(Command::Crypto {
                                command: CryptoCommand::Vigenere {
                                    file,
                                    max_key_len: 20,
                                    output: OutputArg { output: None },
                                },
                            })
                        }
                        "e" => {
                            let file = PathBuf::from(prompt("Ciphertext file: ")?);
                            let kl: usize = prompt("Key length: ")?.parse().context("Must be a number")?;
                            dispatch(Command::Crypto {
                                command: CryptoCommand::Xor {
                                    file,
                                    key_len: kl,
                                    output: OutputArg { output: None },
                                },
                            })
                        }
                        _ => {
                            println!("Invalid choice.");
                            return Ok(());
                        }
                    }
                }
                "11" => {
                    let file = PathBuf::from(prompt("Protocol capture CSV path: ")?);
                    dispatch(Command::Protocol {
                        capture: file,
                        output: OutputArg { output: None },
                    })
                }
                _ => {
                    println!("Choose one of the listed options.");
                    return Ok(());
                }
            };
            if let Err(error) = result {
                eprintln!("error: {error:#}");
            }
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("error: {error:#}");
        }
    }
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

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
