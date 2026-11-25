use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use iq_research_workbench::ai::start_chat;
use iq_research_workbench::{
    AssessmentInput, analyze_iq, analyze_trace, assess_engagement, audit_to_sarif,
    create_manifest, create_scope_file, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace, inspect_firmware_binary, launch_gui,
    scan_source_tree, simulate_qubit, verify_audit_ledger, verify_manifest, verify_scope_file,
};
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "iq-workbench",
    version,
    about = "Authorized offline hardware red-team, IQ, physical trace, and evidence workbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an IQ capture (.csv, .npy, .cf32, .cs8, .cu8) for RF impairments, spurs, and bursts
    Analyze {
        iq_file: PathBuf,
        #[arg(long)]
        sample_rate: Option<f64>,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Screen a physical measurement trace (.csv) for glitches, periodicity, drift, and Welch t-stat
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
    /// Run a unified hardware red-team assessment across IQ, physical trace, and source code
    Assess(Box<AssessArgs>),
    /// Verify a tamper-evident SHA-256 audit ledger (.jsonl)
    Ledger {
        ledger: PathBuf,
    },
    /// Generate legal synthetic lab demo files for testing CLI & GUI
    Sample {
        #[arg(long, default_value = "./demo_lab")]
        output_dir: PathBuf,
    },
    /// Launch the local browser-based graphical workbench (bound to 127.0.0.1)
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
    /// Offline binary firmware surface inspector (entropy, magic, YARA-lite, indicators)
    Firmware {
        /// Path to the firmware binary or flash image file
        firmware: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
    /// Discuss a saved JSON report with an optional AI provider
    Chat(ChatArgs),
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
    Verify {
        path: PathBuf,
    },
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
                std::fs::write(sarif_path, format!("{}\n", serde_json::to_string_pretty(&sarif_doc)?))?;
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
        Command::Sample { output_dir } => write_report(generate_demo_workspace(&output_dir)?, None),
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
            write_report(
                simulate_qubit(&gates, theta, phi)?,
                output.output.as_deref(),
            )
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
             1) IQ capture analysis\n\
             2) Physical measurement trace\n\
             3) Create evidence manifest\n\
             4) Verify evidence manifest\n\
             5) Hardware/Firmware source review\n\
             6) Educational qubit simulation\n\
             7) Ask AI about a report\n\
             8) Launch Graphical Workbench (GUI)\n\
             9) Generate demo lab dataset\n\
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
