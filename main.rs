use anyhow::Result;
use clap::{Parser, Subcommand};

use hw_toolkit::{
    discovery::discover_windows,
    driver::MemoryHardwareSource,
    em_nuclear::{
        assess_radiation_bit_flip, faraday_shielding_db, hemp_e1_field_v_m,
        hemp_induced_pcb_voltage, tempest_eavesdrop_snr_db,
    },
    pentest::{demo_plan, execute_plan, PentestPlan},
    physical_analysis::fingerprint_cpu,
    report::{export_pdf_report, write_html_report, write_json_report, write_markdown_report},
    rf_scan::rf_scan,
    vuln_db::{export_json, filter_by_category, filter_by_severity, search_vulns, vuln_database},
};
use num_complex::Complex64;
use std::f64::consts::PI;

#[derive(Parser)]
#[clap(
    name = "hw_toolkit",
    version = "0.2.0",
    author = "Red Team",
    about = "Full-spectrum hardware, RF, EM/HEMP, Nuclear-SEE & ASM security platform"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Passive discovery of local hardware (USB, serial ports).
    Discover,

    /// Fingerprint the local CPU architecture & ASM security capabilities.
    Cpu,

    /// List all hardware vulnerabilities in the database.
    Vulns {
        #[clap(long, help = "Filter by category (physical/sidechannel/rf/protocol/firmware/architecture/supply)")]
        category: Option<String>,
        #[clap(long, help = "Minimum CVSS score", default_value = "0")]
        min_cvss: f32,
        #[clap(long, help = "Search keyword")]
        search: Option<String>,
        #[clap(long, help = "Export to JSON file")]
        export: Option<String>,
    },

    /// Run an RF scan on synthetic or real IQ data.
    RfScan {
        #[clap(long, help = "Centre frequency in Hz", default_value = "433920000")]
        center: f64,
        #[clap(long, help = "Sample rate in Hz", default_value = "1000000")]
        sr: f64,
        #[clap(long, help = "Number of synthetic IQ samples", default_value = "4096")]
        samples: usize,
    },

    /// Run Electromagnetic (HEMP/Faraday/TEMPEST) & Nuclear Radiation (SEU/LET) physics audit.
    EmNuclear {
        #[clap(long, default_value = "1000000000")]
        freq_hz: f64,
        #[clap(long, default_value = "0.001")]
        shield_m: f64,
        #[clap(long, default_value = "15.0")]
        let_mev: f64,
    },

    /// Execute a pentest plan from a JSON file.
    RunPlan {
        #[clap(long, help = "Path to PentestPlan JSON file")]
        plan: String,
        #[clap(long, help = "Output JSON report path", default_value = "report.json")]
        out_json: String,
        #[clap(long, help = "Output HTML report path", default_value = "report.html")]
        out_html: String,
        #[clap(long, help = "Output Markdown report path", default_value = "report.md")]
        out_md: String,
        #[clap(long, help = "Optional PDF output (requires wkhtmltopdf)")]
        out_pdf: Option<String>,
    },

    /// Run the built-in full-spectrum demo pentest plan.
    Demo {
        #[clap(long, help = "Target device name", default_value = "demo-device")]
        target: String,
        #[clap(long, help = "Output JSON report", default_value = "demo_report.json")]
        out_json: String,
        #[clap(long, help = "Output HTML report", default_value = "demo_report.html")]
        out_html: String,
        #[clap(long, help = "Output Markdown report", default_value = "demo_report.md")]
        out_md: String,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Discover => {
            println!("🔍 Passive hardware discovery...");
            let devices = discover_windows()?;
            println!("Found {} device(s):", devices.len());
            println!("{}", serde_json::to_string_pretty(&devices)?);
        }

        Commands::Cpu => {
            let info = fingerprint_cpu();
            println!("OS CPU Info:\n{}", serde_json::to_string_pretty(&info)?);
            #[cfg(target_arch = "x86_64")]
            {
                let asm_caps = hw_toolkit::asm_payload::asm_cpuid_security_caps();
                let (hit, miss) = hw_toolkit::asm_payload::calibrate_cache_timing_threshold();
                println!("ASM CPUID Security Caps:\n{}", serde_json::to_string_pretty(&asm_caps)?);
                println!("Cache Timing Calibration: hit={} cycles, flush+reload miss={} cycles", hit, miss);
            }
        }

        Commands::Vulns { category, min_cvss, search, export } => {
            let db = vuln_database();
            let filtered: Vec<_> = if let Some(ref q) = search {
                search_vulns(&db, q)
            } else if let Some(ref cat) = category {
                filter_by_category(&db, cat)
            } else {
                filter_by_severity(&db, min_cvss)
            };
            println!("Found {} vulnerability/vulnerabilities:", filtered.len());
            for v in &filtered {
                println!("\n[{}] {} (CVSS {:.1})", v.id, v.name, v.cvss_score);
                println!("  Category   : {:?}", v.category);
                println!("  Severity   : {:?}", v.severity);
                println!("  Description: {}", &v.description[..v.description.len().min(120)]);
                println!("  Mitigation : {}", v.mitigation);
            }
            if let Some(path) = export {
                let json = export_json(&db)?;
                std::fs::write(&path, json)?;
                println!("\nExported to {}", path);
            }
        }

        Commands::RfScan { center, sr, samples } => {
            println!("📡 RF scan @ {:.3} MHz, SR={:.1} MHz, N={}", center / 1e6, sr / 1e6, samples);
            let iq: Vec<Complex64> = (0..samples).map(|i| {
                let t = i as f64 / sr;
                let sig = Complex64::new((2.0 * PI * 100_000.0 * t).cos(), (2.0 * PI * 100_000.0 * t).sin());
                sig * 0.5 + Complex64::new(0.01 * ((i * 7) % 100) as f64 / 100.0, 0.0)
            }).collect();
            let report = rf_scan(&iq, center, sr, 30.0);
            println!("{}", serde_json::to_string_pretty(&report)?);
        }

        Commands::EmNuclear { freq_hz, shield_m, let_mev } => {
            let shield = faraday_shielding_db(freq_hz, shield_m, 1.0, 5.8e7);
            let hemp_e = hemp_e1_field_v_m(4e-9, 50_000.0, 1.3, 4e7, 6e8);
            let hemp_v = hemp_induced_pcb_voltage(50_000.0, 0.05, 1e-4, shield.total_se_db, 2.5e-9);
            let tempest = tempest_eavesdrop_snr_db(freq_hz, 0.01, 0.03, 10.0, shield.total_se_db, 1e6, 3.0);
            let seu = assess_radiation_bit_flip(2.0, 1.2, let_mev, 1.0);
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "copper_faraday_shield": shield,
                "hemp_e1_4ns_v_m": hemp_e,
                "hemp_induced_pcb_v": hemp_v,
                "tempest_snr_10m_db": tempest,
                "radiation_seu_assessment": seu,
            }))?);
        }

        Commands::RunPlan { plan, out_json, out_html, out_md, out_pdf } => {
            let plan_json = std::fs::read_to_string(&plan)?;
            let plan: PentestPlan = serde_json::from_str(&plan_json)?;
            let trace: Vec<f64> = (0..8192).map(|i| (i as f64 * 0.001).sin() * 0.1 + 3.3).collect();
            let iq: Vec<Complex64> = (0..8192).map(|i| {
                let t = i as f64 / 8192.0 * PI * 2.0;
                Complex64::new(t.sin() * 0.5, t.cos() * 0.5)
            }).collect();
            let mut driver = MemoryHardwareSource::new("plan-driver", 1e6)
                .with_trace(trace).with_iq(iq);
            println!("🔴 Executing pentest plan: {}", plan.target);
            let report = execute_plan(&mut driver, &plan)?;
            write_json_report(&report, &out_json)?;
            write_html_report(&report, &out_html)?;
            write_markdown_report(&report, &out_md)?;
            println!("\n📊 Risk Score: {:.1}/100", report.risk_score);
            println!("   {}/{} attacks succeeded", report.succeeded, report.total_attacks);
            println!("   Reports: {}, {}, {}", out_json, out_html, out_md);
            if let Some(pdf) = out_pdf {
                match export_pdf_report(&out_html, &pdf) {
                    Ok(_) => println!("   PDF: {}", pdf),
                    Err(e) => eprintln!("   PDF skipped: {}", e),
                }
            }
        }

        Commands::Demo { target, out_json, out_html, out_md } => {
            let plan = demo_plan(&target);
            let trace: Vec<f64> = (0..8192).map(|i| (i as f64 * 0.001).sin() * 0.1 + 3.3).collect();
            let iq: Vec<Complex64> = (0..8192).map(|i| {
                let t = i as f64 / 8192.0 * PI * 2.0;
                Complex64::new(t.sin() * 0.5, t.cos() * 0.5)
            }).collect();
            let mut driver = MemoryHardwareSource::new("demo-driver", 1e6)
                .with_trace(trace).with_iq(iq);
            println!("🔴 Running DEMO full-spectrum pentest on '{}'", target);
            let report = execute_plan(&mut driver, &plan)?;
            write_json_report(&report, &out_json)?;
            write_html_report(&report, &out_html)?;
            write_markdown_report(&report, &out_md)?;
            println!("\n📊 Risk Score: {:.1}/100", report.risk_score);
            println!("   {}/{} attacks succeeded", report.succeeded, report.total_attacks);
            println!("\n📋 Recommendations:");
            for rec in &report.recommendations { println!("   • {}", rec); }
            println!("\n   Reports written: {}, {}, {}", out_json, out_html, out_md);
        }
    }

    Ok(())
}
