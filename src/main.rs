use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use iq_research_workbench::ai::start_chat;
use iq_research_workbench::{
    analyze_iq, analyze_trace, create_manifest, scan_source_tree, simulate_qubit, verify_manifest,
};
use serde_json::Value;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "iq-workbench",
    version,
    about = "Offline workbench for IQ, evidence, physical traces, source review, and quantum education"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Analyze {
        iq_file: PathBuf,
        #[arg(long)]
        sample_rate: Option<f64>,
        #[command(flatten)]
        output: OutputArg,
    },
    Physical {
        trace: PathBuf,
        #[arg(long)]
        reference: Option<PathBuf>,
        #[arg(long, default_value_t = 6.0)]
        threshold: f64,
        #[command(flatten)]
        output: OutputArg,
    },
    Forensic {
        #[command(subcommand)]
        command: ForensicCommand,
    },
    Audit {
        root: PathBuf,
        #[command(flatten)]
        output: OutputArg,
    },
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
    if output.is_some_and(|output| absolute_path(&output).starts_with(absolute_path(root))) {
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
        Command::Audit { root, output } => {
            ensure_output_outside(&output.output, &root)?;
            write_report(scan_source_tree(&root)?, output.output.as_deref())
        }
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
            "\nIQ Research Workbench (Rust)\n\
             1) IQ capture analysis\n\
             2) Physical measurement trace\n\
             3) Create evidence manifest\n\
             4) Verify evidence manifest\n\
             5) Local source review\n\
             6) Educational qubit simulation\n\
             7) Ask AI about a report\n\
             0) Exit"
        );
        let choice = prompt("Choose: ")?;
        if choice.is_empty() || matches!(choice.as_str(), "0" | "exit" | "quit") {
            return Ok(());
        }
        let result = (|| -> Result<()> {
            let result = match choice.as_str() {
                "1" => {
                    let path = PathBuf::from(prompt("IQ CSV/NPY path: ")?);
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
