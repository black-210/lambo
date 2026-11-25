use crate::audit::{audit_to_sarif, scan_source_tree};
use crate::common::sha256_bytes;
use crate::legal::{append_audit_entry, verify_scope_file};
use crate::physical::analyze_trace;
use crate::signal::analyze_iq;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::f64::consts::PI;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default)]
pub struct AssessmentInput {
    pub iq_file: Option<PathBuf>,
    pub sample_rate_hz: Option<f64>,
    pub physical_trace: Option<PathBuf>,
    pub physical_reference: Option<PathBuf>,
    pub physical_threshold: f64,
    pub source_dir: Option<PathBuf>,
    pub scope_file: Option<PathBuf>,
    pub ledger_file: Option<PathBuf>,
}

fn risk_band(score: u64) -> &'static str {
    match score {
        0..=19 => "low",
        20..=44 => "moderate",
        45..=69 => "elevated",
        _ => "high",
    }
}

pub fn assess_engagement(input: &AssessmentInput) -> Result<Value> {
    if input.iq_file.is_none() && input.physical_trace.is_none() && input.source_dir.is_none() {
        bail!("Provide at least one input: iq_file, physical_trace, or source_dir.");
    }

    let scope = match input.scope_file.as_deref() {
        Some(path) => Some(verify_scope_file(path)?),
        None => None,
    };
    let iq = match input.iq_file.as_deref() {
        Some(path) => Some(analyze_iq(path, input.sample_rate_hz)?),
        None => None,
    };
    let physical = match input.physical_trace.as_deref() {
        Some(path) => {
            let threshold = if input.physical_threshold > 0.0 {
                input.physical_threshold
            } else {
                6.0
            };
            Some(analyze_trace(
                path,
                input.physical_reference.as_deref(),
                threshold,
            )?)
        }
        None => None,
    };
    let audit = match input.source_dir.as_deref() {
        Some(path) => Some(scan_source_tree(path)?),
        None => None,
    };

    let mut scores = Vec::new();
    let mut highlights = Vec::new();

    if let Some(ref iq_rep) = iq {
        let s = iq_rep["metrics"]["anomaly_score"].as_u64().unwrap_or(0);
        scores.push(s);
        if let Some(flags) = iq_rep["anomaly_flags"].as_array() {
            for f in flags {
                if let Some(txt) = f.as_str() {
                    highlights.push(format!("IQ/RF indicator: {txt}"));
                }
            }
        }
    }
    if let Some(ref phys_rep) = physical {
        let s = phys_rep["metrics"]["anomaly_score"].as_u64().unwrap_or(0);
        scores.push(s);
        if let Some(flags) = phys_rep["anomaly_flags"].as_array() {
            for f in flags {
                if let Some(txt) = f.as_str() {
                    highlights.push(format!("Physical trace indicator: {txt}"));
                }
            }
        }
    }
    if let Some(ref aud_rep) = audit {
        let s = aud_rep["metrics"]["risk_score"].as_u64().unwrap_or(0);
        scores.push(s);
        let count = aud_rep["metrics"]["finding_count"].as_u64().unwrap_or(0);
        if count > 0 {
            highlights.push(format!(
                "Firmware/hardware static scan reported {count} pattern finding(s)."
            ));
        }
    }

    let overall_score = if scores.is_empty() {
        0
    } else {
        let max_s = *scores.iter().max().unwrap_or(&0);
        let avg_s = scores.iter().sum::<u64>() / scores.len() as u64;
        ((max_s * 6 + avg_s * 4) / 10).min(100)
    };

    let mut report = json!({
        "schema_version": 2,
        "analysis": "unified_hardware_redteam_assessment",
        "legal_authorized": scope.is_some(),
        "scope": scope,
        "summary": {
            "overall_score": overall_score,
            "risk_level": risk_band(overall_score),
            "modules_executed": {
                "iq_analysis": iq.is_some(),
                "physical_trace": physical.is_some(),
                "hardware_source_audit": audit.is_some()
            },
            "highlights": highlights
        },
        "iq_report": iq,
        "physical_report": physical,
        "audit_report": audit,
        "limitations": [
            "All analyses are offline and non-destructive on user-supplied local artifacts.",
            "Scores indicate screening priority for authorized experts, not confirmed exploitability.",
            "Maintain written authorization and instrument calibration logs for all hardware engagements."
        ]
    });

    let report_sha = sha256_bytes(serde_json::to_string(&report)?.as_bytes());
    report["report_sha256"] = json!(report_sha);

    if let Some(ledger_path) = input.ledger_file.as_deref() {
        let scope_sha = report["scope"]["scope_sha256"].as_str();
        let summary = format!(
            "score={}, risk={}",
            overall_score,
            report["summary"]["risk_level"].as_str().unwrap_or("low")
        );
        let entry = append_audit_entry(
            ledger_path,
            "unified_assessment",
            scope_sha,
            &report_sha,
            &summary,
        )?;
        report["ledger_entry"] = serde_json::to_value(entry)?;
    }

    Ok(report)
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn export_html_report(report: &Value, output_path: &Path) -> Result<()> {
    let score = report["summary"]["overall_score"].as_u64().unwrap_or_else(|| {
        report["metrics"]["anomaly_score"]
            .as_u64()
            .or_else(|| report["metrics"]["risk_score"].as_u64())
            .unwrap_or(0)
    });
    let risk = report["summary"]["risk_level"]
        .as_str()
        .unwrap_or("assessed");
    let analysis = report["analysis"].as_str().unwrap_or("workbench_report");
    let pretty_json = serde_json::to_string_pretty(report)?;
    let highlights = report["summary"]["highlights"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| format!("<li>{}</li>", html_escape(s)))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>IQ Hardware Red-Team Assessment Report</title>
<style>
body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 32px; }}
.wrap {{ max-width: 980px; margin: 0 auto; }}
.card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; margin-bottom: 20px; }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 999px; background: #1f6feb33; border: 1px solid #58a6ff; color: #58a6ff; font-weight: 600; }}
.score {{ font-size: 2.2rem; font-weight: 700; color: #79c0ff; }}
pre {{ background: #0b0f14; border: 1px solid #30363d; border-radius: 8px; padding: 14px; overflow-x: auto; font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <span class="badge">{analysis}</span>
    <h1>Hardware &amp; Physical Security Assessment Report</h1>
    <div class="score">Score: {score}/100 ({risk})</div>
    <p>Generated strictly from authorized offline local artifacts.</p>
  </div>
  <div class="card">
    <h2>Key Screening Highlights</h2>
    <ul>{highlights}</ul>
  </div>
  <div class="card">
    <h2>Full Machine-Readable Report (JSON)</h2>
    <pre>{json_body}</pre>
  </div>
</div>
</body>
</html>
"#,
        analysis = html_escape(analysis),
        score = score,
        risk = html_escape(risk),
        highlights = if highlights.is_empty() {
            "<li>See full JSON report below.</li>".to_owned()
        } else {
            highlights
        },
        json_body = html_escape(&pretty_json)
    );
    fs::write(output_path, html)
        .with_context(|| format!("Writing HTML report {}", output_path.display()))?;
    Ok(())
}

pub fn export_markdown_report(report: &Value, output_path: &Path) -> Result<()> {
    let score = report["summary"]["overall_score"].as_u64().unwrap_or(0);
    let risk = report["summary"]["risk_level"].as_str().unwrap_or("assessed");
    let authorized = report["legal_authorized"].as_bool().unwrap_or(false);
    let sha = report["report_sha256"].as_str().unwrap_or("n/a");
    let mut md = format!(
        "# Hardware & Physical Security Assessment Report\n\n\
         - **Overall Score:** {score}/100 (`{risk}`)\n\
         - **Legal Scope Verified:** `{authorized}`\n\
         - **Report SHA-256:** `{sha}`\n\n\
         ## Highlights\n\n"
    );
    if let Some(highlights) = report["summary"]["highlights"].as_array() {
        for item in highlights {
            if let Some(text) = item.as_str() {
                md.push_str(&format!("- {text}\n"));
            }
        }
    }
    if let Some(findings) = report["audit_report"]["findings"].as_array()
        && !findings.is_empty()
    {
        md.push_str("\n## Hardware & Firmware Static Findings\n\n| Severity | Rule | CWE | Location |\n|---|---|---|---|\n");
        for f in findings.iter().take(50) {
            md.push_str(&format!(
                "| {} | `{}` | {} | `{}:{}` |\n",
                f["severity"].as_str().unwrap_or(""),
                f["rule_id"].as_str().unwrap_or(""),
                f["cwe"].as_str().unwrap_or(""),
                f["path"].as_str().unwrap_or(""),
                f["line"].as_u64().unwrap_or(0),
            ));
        }
    }
    fs::write(output_path, md)
        .with_context(|| format!("Writing Markdown report {}", output_path.display()))?;
    Ok(())
}

pub fn export_sarif_report(report: &Value, output_path: &Path) -> Result<()> {
    let audit_node = if report.get("audit_report").is_some_and(Value::is_object) {
        &report["audit_report"]
    } else {
        report
    };
    let sarif = audit_to_sarif(audit_node)?;
    fs::write(output_path, format!("{}\n", serde_json::to_string_pretty(&sarif)?))
        .with_context(|| format!("Writing SARIF report {}", output_path.display()))?;
    Ok(())
}

pub fn generate_demo_workspace(output_dir: &Path) -> Result<Value> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Creating demo directory {}", output_dir.display()))?;

    let scope_path = output_dir.join("scope.json");
    crate::legal::create_scope_file(&scope_path, "LAB-DEMO-2026", "hardware-redteam-lead")?;

    let iq_path = output_dir.join("iq_capture_demo.csv");
    let mut iq_csv = String::from("I,Q\n");
    for idx in 0..512 {
        let angle = 2.0 * PI * 24.0 * idx as f64 / 512.0;
        let burst = if (200..235).contains(&idx) { 2.8 } else { 1.0 };
        let spur = 0.25 * (2.0 * PI * 71.0 * idx as f64 / 512.0).cos();
        let i = burst * (1.25 * angle.cos() + spur) + 0.22;
        let q = burst * (0.75 * (angle + 0.18).sin()) - 0.08;
        iq_csv.push_str(&format!("{i:.6},{q:.6}\n"));
    }
    fs::write(&iq_path, iq_csv)?;

    let trace_path = output_dir.join("physical_trace_demo.csv");
    let ref_path = output_dir.join("physical_reference_demo.csv");
    let mut trace_csv = String::from("time,measurement\n");
    let mut ref_csv = String::from("time,measurement\n");
    for idx in 0..256 {
        let base = 1.0 + 0.35 * (2.0 * PI * 16.0 * idx as f64 / 256.0).sin();
        let ref_val = 1.0 + 0.12 * (2.0 * PI * 16.0 * idx as f64 / 256.0).sin();
        let glitch = if idx == 95 || idx == 180 { 4.8 } else { 0.0 };
        trace_csv.push_str(&format!("{idx},{:.6}\n", base + glitch));
        ref_csv.push_str(&format!("{idx},{ref_val:.6}\n"));
    }
    fs::write(&trace_path, trace_csv)?;
    fs::write(&ref_path, ref_csv)?;

    let fw_dir = output_dir.join("sample_firmware");
    fs::create_dir_all(&fw_dir)?;
    fs::write(
        fw_dir.join("board_config.cfg"),
        "ENABLE_JTAG=1\nSECURE_BOOT=0\nUART_DEBUG_CONSOLE=1\nWDT_DISABLE=1\n",
    )?;
    fs::write(
        fw_dir.join("uart_driver.c"),
        "void log_msg(char *dst, const char *src) {\n    strcpy(dst, src);\n}\n",
    )?;

    Ok(json!({
        "schema_version": 1,
        "analysis": "synthetic_lab_demo_generated",
        "output_dir": output_dir.to_string_lossy(),
        "files": {
            "scope": scope_path.to_string_lossy(),
            "iq_capture": iq_path.to_string_lossy(),
            "physical_trace": trace_path.to_string_lossy(),
            "physical_reference": ref_path.to_string_lossy(),
            "firmware_dir": fw_dir.to_string_lossy()
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn generates_demo_and_runs_unified_assessment() {
        let dir = std::env::temp_dir().join(format!(
            "iq-assess-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let demo = generate_demo_workspace(&dir).unwrap();
        let report = assess_engagement(&AssessmentInput {
            iq_file: Some(PathBuf::from(demo["files"]["iq_capture"].as_str().unwrap())),
            sample_rate_hz: Some(2_000_000.0),
            physical_trace: Some(PathBuf::from(demo["files"]["physical_trace"].as_str().unwrap())),
            physical_reference: Some(PathBuf::from(
                demo["files"]["physical_reference"].as_str().unwrap(),
            )),
            physical_threshold: 6.0,
            source_dir: Some(PathBuf::from(demo["files"]["firmware_dir"].as_str().unwrap())),
            scope_file: Some(PathBuf::from(demo["files"]["scope"].as_str().unwrap())),
            ledger_file: Some(dir.join("audit_ledger.jsonl")),
        })
        .unwrap();

        assert_eq!(report["legal_authorized"], true);
        assert!(report["summary"]["overall_score"].as_u64().unwrap() > 20);
        let html_path = dir.join("report.html");
        let md_path = dir.join("report.md");
        let sarif_path = dir.join("report.sarif");
        export_html_report(&report, &html_path).unwrap();
        export_markdown_report(&report, &md_path).unwrap();
        export_sarif_report(&report, &sarif_path).unwrap();
        assert!(html_path.exists() && md_path.exists() && sarif_path.exists());
        fs::remove_dir_all(dir).unwrap();
    }
}
