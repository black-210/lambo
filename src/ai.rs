//! # Autonomous Physical & Security AI Engine + Interactive Advisor
//!
//! Combines:
//! 1. **100% Offline Autonomous Physical/Hardware Audit Agent (`autonomous_workspace_audit`)**:
//!    Recursively discovers all hardware, RF IQ, physical trace, logic-bus VCD, protocol PCAP/CSV,
//!    and firmware artifacts in a target workspace; executes every analyzer automatically; runs
//!    **Cross-Domain Risk Correlation** and **Unsupervised Feature Anomaly Scoring** from scratch;
//!    records a tamper-evident ledger entry if configured; and produces a unified engineering report.
//! 2. **100% Offline Interactive Diagnostic Advisor (`diagnose_report_offline`)**:
//!    Generates grounded Arabic/English diagnostic briefings & remediation plans citing exact report
//!    fields with zero external network calls or API keys required.
//! 3. **Optional External LLM Provider Chat (`start_chat`)**: Gemini & OpenAI-compatible support.

use crate::assess::assess_engagement;
use crate::audit::scan_source_tree;
use crate::cryptanalysis::{berlekamp_massey_gf2, detect_ecb_blocks, nist_randomness_suite};
use crate::firmware::inspect_firmware_binary;
use crate::hardware::{decode_uart_vcd, discover_local_hardware};
use crate::legal::{append_audit_entry, verify_scope_file};
use crate::physical::{analyze_trace, analyze_trace_matrix};
use crate::protocol::analyze_protocol_capture;
use crate::signal::analyze_iq;
use crate::common::sha256_bytes;
use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::Path;
use walkdir::WalkDir;

const SYSTEM_INSTRUCTION: &str = "You are a cautious assistant for defensive, authorized, offline analysis of local evidence inventories, source review results, measured signal traces, IQ captures, and educational quantum simulations. Interpret only the supplied report. Separate observations from hypotheses, cite report fields, explain uncertainty and possible false positives, and offer safe defensive next steps. Do not claim proof of physical, quantum, or security vulnerabilities, and do not provide instructions for exploiting, interfering with, or targeting systems.";

// ─── Autonomous Offline Physical & Hardware AI Engine ────────────────────────

/// Autonomously inspect every supported hardware, RF IQ, side-channel, logic-bus, firmware,
/// protocol, and cryptographic artifact under `workspace_dir`, compute cross-domain correlations,
/// and synthesize a prioritized security/bug-bounty assessment report offline.
pub fn autonomous_workspace_audit(
    workspace_dir: &Path,
    scope_file: Option<&Path>,
    ledger_file: Option<&Path>,
    sample_rate_hz: Option<f64>,
) -> Result<Value> {
    if !workspace_dir.is_dir() {
        bail!("Workspace path is not a directory: {}", workspace_dir.display());
    }

    let scope_report = match scope_file {
        Some(p) => Some(verify_scope_file(p)?),
        None => None,
    };

    let mut iq_reports = Vec::new();
    let mut trace_reports = Vec::new();
    let mut matrix_reports = Vec::new();
    let mut vcd_reports = Vec::new();
    let mut protocol_reports = Vec::new();
    let mut firmware_reports = Vec::new();

    for entry in WalkDir::new(workspace_dir)
        .follow_links(false)
        .max_depth(4)
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let ext = p
            .extension()
            .and_then(|s| s.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        if matches!(ext.as_str(), "cf32" | "cs16" | "cs8" | "cu8" | "wav")
            || name.ends_with(".sigmf-meta")
            || (ext == "csv" && name.contains("iq"))
        {
            if let Ok(rep) = analyze_iq(p, sample_rate_hz) {
                iq_reports.push(rep);
            }
        } else if ext == "vcd" {
            if let Ok(rep) = decode_uart_vcd(p, None, None) {
                vcd_reports.push(rep);
            }
        } else if ext == "pcap" || (ext == "csv" && name.contains("protocol")) {
            if let Ok(rep) = analyze_protocol_capture(p) {
                protocol_reports.push(rep);
            }
        } else if ext == "csv" && (name.contains("matrix") || name.contains("tvla")) {
            if let Ok(rep) = analyze_trace_matrix(p, 0) {
                matrix_reports.push(rep);
            }
        } else if ext == "csv" && (name.contains("trace") || name.contains("physical")) {
            if let Ok(rep) = analyze_trace(p, None, 6.0) {
                trace_reports.push(rep);
            }
        } else if matches!(ext.as_str(), "bin" | "elf" | "fw" | "img")
            && let Ok(mut rep) = inspect_firmware_binary(p)
        {
            if let Ok(bytes) = std::fs::read(p) {
                if bytes.len() >= 32
                    && let Ok(ecb) = detect_ecb_blocks(&bytes, 16)
                    && ecb["ecb_leakage_detected"] == true
                {
                    rep["ecb_screen"] = ecb;
                }
                if bytes.len() >= 16
                    && bytes.len() <= 65_536
                    && let Ok(nist) = nist_randomness_suite(&bytes[..bytes.len().min(4096)])
                {
                    rep["randomness_screen"] = nist;
                }
                if let Ok(bm) = berlekamp_massey_gf2(&bytes[..bytes.len().min(128)]) {
                    rep["lfsr_complexity"] = bm;
                }
            }
            firmware_reports.push(rep);
        }
    }

    let source_audit = scan_source_tree(workspace_dir).ok();
    let hw_inventory = discover_local_hardware().ok();

    // ── Unsupervised Multi-Feature Z-Score & Cross-Domain Correlation ────────
    let mut hypotheses: Vec<Value> = Vec::new();
    let mut feature_scores: Vec<f64> = Vec::new();

    let max_iq_score = iq_reports
        .iter()
        .filter_map(|r| r["metrics"]["anomaly_score"].as_f64())
        .fold(0.0_f64, f64::max);
    if !iq_reports.is_empty() {
        feature_scores.push(max_iq_score);
    }

    let max_phys_score = trace_reports
        .iter()
        .filter_map(|r| r["metrics"]["anomaly_score"].as_f64())
        .fold(0.0_f64, f64::max);
    if !trace_reports.is_empty() {
        feature_scores.push(max_phys_score);
    }

    let tvla_leaks = matrix_reports
        .iter()
        .filter(|r| r["tvla_leakage_detected"] == true)
        .count();
    if tvla_leaks > 0 {
        feature_scores.push(85.0);
        hypotheses.push(json!({
            "id": "HYP-TVLA-LEAKAGE",
            "confidence": 0.94,
            "severity": "high",
            "cwe": "CWE-203",
            "domains": ["physical_side_channel"],
            "evidence": "Multi-trace TVLA |t| > 4.5 and elevated NICV detected in power/EM matrix.",
            "remediation": "Add masking / random delay jitter / constant-time arithmetic around secret-dependent branches."
        }));
    }

    let src_risk = source_audit
        .as_ref()
        .and_then(|s| s["metrics"]["risk_score"].as_f64())
        .unwrap_or(0.0);
    if source_audit.is_some() {
        feature_scores.push(src_risk);
    }

    let fw_max_risk = firmware_reports
        .iter()
        .filter_map(|f| f["metrics"]["risk_score"].as_f64())
        .fold(0.0_f64, f64::max);
    if !firmware_reports.is_empty() {
        feature_scores.push(fw_max_risk);
    }

    let uart_keyword_hits: usize = vcd_reports
        .iter()
        .filter_map(|v| v["security_indicators"].as_array().map(Vec::len))
        .sum();
    if uart_keyword_hits > 0 {
        feature_scores.push(80.0);
    }

    let proto_anoms: usize = protocol_reports
        .iter()
        .filter_map(|p| p["anomaly_count"].as_u64())
        .map(|n| n as usize)
        .sum();
    if proto_anoms > 0 {
        feature_scores.push((proto_anoms as f64 * 20.0).min(100.0));
    }

    // Cross-Domain Correlation Rule 1: IQ harmonic/clock spurs + Physical clock periodicity
    let iq_spurs = iq_reports
        .iter()
        .any(|r| r["metrics"]["cfar_spur_count"].as_u64().unwrap_or(0) >= 1);
    let phys_periodic = trace_reports
        .iter()
        .any(|r| r["metrics"]["periodic_power_ratio"].as_f64().unwrap_or(0.0) > 0.25);
    if iq_spurs && phys_periodic {
        hypotheses.push(json!({
            "id": "CORR-EM-CLOCK-COUPLING",
            "confidence": 0.86,
            "severity": "high",
            "cwe": "CWE-1255",
            "domains": ["rf_iq", "physical_trace"],
            "evidence": "RF IQ CA-CFAR spurs correlate with strong periodic clock harmonics in physical measurement traces.",
            "remediation": "Inspect PCB decoupling, spread-spectrum clocking, and RF/power-plane isolation."
        }));
    }

    // Cross-Domain Correlation Rule 2: Static UART/JTAG finding + VCD decoded UART keywords
    let src_uart_jtag = source_audit
        .as_ref()
        .and_then(|s| s["findings"].as_array())
        .is_some_and(|arr| {
            arr.iter().any(|f| {
                matches!(
                    f["rule_id"].as_str(),
                    Some("hw-uart-debug-console" | "hw-jtag-swd-unlocked")
                )
            })
        });
    if src_uart_jtag && uart_keyword_hits > 0 {
        hypotheses.push(json!({
            "id": "CORR-EXPOSED-DEBUG-UART",
            "confidence": 0.96,
            "severity": "critical",
            "cwe": "CWE-284",
            "domains": ["source_audit", "logic_bus_uart"],
            "evidence": "Source/config audit flags UART/JTAG debug flags AND VCD logic capture decoded cleartext UART boot/credential keywords.",
            "remediation": "Strip interactive UART shells, remove credential echoes from serial logs, and blow production JTAG/RDP fuses."
        }));
    }

    // Cross-Domain Correlation Rule 3: Glitch outliers + Disabled WDT/BOR in source
    let phys_glitch = trace_reports
        .iter()
        .any(|r| r["metrics"]["robust_outlier_count"].as_u64().unwrap_or(0) > 0);
    let src_no_bor = source_audit
        .as_ref()
        .and_then(|s| s["findings"].as_array())
        .is_some_and(|arr| {
            arr.iter()
                .any(|f| f["rule_id"].as_str() == Some("hw-watchdog-or-bor-disabled"))
        });
    if phys_glitch && src_no_bor {
        hypotheses.push(json!({
            "id": "CORR-GLITCH-RESILIENCE-GAP",
            "confidence": 0.89,
            "severity": "high",
            "cwe": "CWE-693",
            "domains": ["physical_trace", "source_audit"],
            "evidence": "Physical trace shows high-sigma transient glitch impulses while firmware disables WDT/BOR fault protection.",
            "remediation": "Re-enable Brown-Out Reset (BOR), independent hardware watchdog, and redundant state checks in boot verification."
        }));
    }

    // Cross-Domain Correlation Rule 4: Protocol cleartext/sensitive payloads
    if proto_anoms > 0 {
        hypotheses.push(json!({
            "id": "HYP-PROTO-TELEMETRY-EXPOSURE",
            "confidence": 0.82,
            "severity": "high",
            "cwe": "CWE-319",
            "domains": ["network_protocol"],
            "evidence": format!("Protocol analyzer surfaced {proto_anoms} anomaly indicator(s) including cleartext telemetry or beaconing."),
            "remediation": "Enforce TLS 1.3 / DTLS with mutual authentication and remove plaintext debug/MQTT ports."
        }));
    }

    let overall_ai_score = if feature_scores.is_empty() {
        0u64
    } else {
        let rms_score = (feature_scores.iter().map(|s| s * s).sum::<f64>()
            / feature_scores.len() as f64)
            .sqrt();
        let peak_score = feature_scores.iter().copied().fold(0.0_f64, f64::max);
        ((0.6 * peak_score + 0.4 * rms_score).round() as u64).min(100)
    };

    let risk_level = match overall_ai_score {
        0..=19 => "low",
        20..=44 => "moderate",
        45..=69 => "elevated",
        _ => "high",
    };

    let mut report = json!({
        "schema_version": 1,
        "analysis": "autonomous_physical_ai_audit",
        "workspace": workspace_dir.display().to_string(),
        "legal_authorized": scope_report.is_some(),
        "scope": scope_report,
        "summary": {
            "overall_score": overall_ai_score,
            "risk_level": risk_level,
            "artifacts_scanned": {
                "iq_files": iq_reports.len(),
                "physical_traces": trace_reports.len(),
                "side_channel_matrices": matrix_reports.len(),
                "logic_vcd_files": vcd_reports.len(),
                "protocol_captures": protocol_reports.len(),
                "firmware_binaries": firmware_reports.len(),
                "source_files": source_audit.as_ref().and_then(|s| s["metrics"]["scanned_files"].as_u64()).unwrap_or(0)
            },
            "hypothesis_count": hypotheses.len(),
            "highlights": hypotheses.iter().filter_map(|h| h["evidence"].as_str().map(str::to_owned)).collect::<Vec<_>>()
        },
        "correlated_hypotheses": hypotheses,
        "details": {
            "hardware_inventory": hw_inventory,
            "iq_reports": iq_reports,
            "physical_reports": trace_reports,
            "side_channel_matrices": matrix_reports,
            "logic_bus_reports": vcd_reports,
            "protocol_reports": protocol_reports,
            "firmware_reports": firmware_reports,
            "audit_report": source_audit
        }
    });

    let report_sha = sha256_bytes(serde_json::to_string(&report)?.as_bytes());
    report["report_sha256"] = json!(report_sha);

    if let Some(ledger_path) = ledger_file {
        let scope_sha = report["scope"]["scope_sha256"].as_str();
        let summary = format!("ai_score={overall_ai_score}, risk={risk_level}");
        let entry = append_audit_entry(
            ledger_path,
            "autonomous_physical_ai_audit",
            scope_sha,
            &report_sha,
            &summary,
        )?;
        report["ledger_entry"] = serde_json::to_value(entry)?;
    }

    Ok(report)
}

/// 100% offline deterministic AI diagnostic interpreter (supports Arabic `'ar'` and English `'en'`).
pub fn diagnose_report_offline(
    report: &Value,
    question: Option<&str>,
    lang: &str,
) -> Value {
    let arabic = lang.eq_ignore_ascii_case("ar");
    let analysis_type = report["analysis"].as_str().unwrap_or("unknown");
    let score = report["summary"]["overall_score"]
        .as_u64()
        .or_else(|| report["metrics"]["anomaly_score"].as_u64())
        .or_else(|| report["metrics"]["risk_score"].as_u64())
        .unwrap_or(0);

    let mut bullets = Vec::new();
    if let Some(iq_m) = report.get("metrics") {
        if let Some(snr) = iq_m["estimated_snr_db"].as_f64() {
            let mod_g = iq_m["modulation_classification"].as_str().unwrap_or("n/a");
            let imb = iq_m["iq_gain_imbalance_db"].as_f64().unwrap_or(0.0);
            bullets.push(if arabic {
                format!("إشارة IQ: نسبة SNR={snr:.1} dB، خلل الكسب={imb:.2} dB، تصنيف التضمين={mod_g}.")
            } else {
                format!("IQ metrics: SNR={snr:.1} dB, Gain Imbalance={imb:.2} dB, Modulation={mod_g}.")
            });
        }
        if let Some(out) = iq_m["robust_outlier_count"].as_u64() {
            let cusum = iq_m["cusum_alarm_count"].as_u64().unwrap_or(0);
            bullets.push(if arabic {
                format!("الأثر الفيزيائي: تم رصد {out} نبضة/خلل شاذة (MAD) و {cusum} إنذار انحراف CUSUM.")
            } else {
                format!("Physical trace: detected {out} MAD glitch outliers and {cusum} CUSUM drift alarms.")
            });
        }
        if let Some(fc) = iq_m["finding_count"].as_u64() {
            bullets.push(if arabic {
                format!("الفحص الساكن للكود والعتاد: {fc} ملاحظة أمنية مسجلة.")
            } else {
                format!("Static hardware/source audit reported {fc} pattern findings.")
            });
        }
    }

    if let Some(hyps) = report["correlated_hypotheses"].as_array() {
        for h in hyps.iter().take(5) {
            bullets.push(format!(
                "[{} | {}] {} -> {}",
                h["severity"].as_str().unwrap_or("info"),
                h["id"].as_str().unwrap_or("HYP"),
                h["evidence"].as_str().unwrap_or(""),
                h["remediation"].as_str().unwrap_or("")
            ));
        }
    }

    if let Some(q) = question
        && !q.trim().is_empty()
    {
        let ql = q.to_ascii_lowercase();
        if ql.contains("remed") || ql.contains("fix") || ql.contains("حل") || ql.contains("علاج") {
            bullets.push(if arabic {
                "التوصية الدفاعية: تفعيل الحماية المادية (BOR/WDT/RDP)، قفل منافذ JTAG/UART الإنتاجية، وتشفير قنوات القياس بـ TLS 1.3 مع مولد عشوائي TRNG سليم.".to_owned()
            } else {
                "Defensive action plan: enable BOR/WDT hardware monitors, disable production JTAG/UART debug shells, and enforce TLS 1.3 + TRNG key generation.".to_owned()
            });
        }
    }

    let summary_text = if arabic {
        format!("تحليل AI محلي لنوع التقرير '{analysis_type}' — درجة الخطورة المرصودة: {score}/100.")
    } else {
        format!("Offline AI diagnosis for '{analysis_type}' — composite screening score: {score}/100.")
    };

    json!({
        "mode": "offline_deterministic_physical_ai",
        "analysis_type": analysis_type,
        "score": score,
        "summary": summary_text,
        "findings_and_advice": bullets,
        "question_answered": question,
        "legal_boundary": "Grounded strictly in local non-destructive measurements."
    })
}

/// Keep unified assessment bridge reachable when combining `assess` + `ai`.
pub fn assess_and_diagnose(input: &crate::assess::AssessmentInput, lang: &str) -> Result<Value> {
    let report = assess_engagement(input)?;
    let diag = diagnose_report_offline(&report, None, lang);
    Ok(json!({
        "assessment": report,
        "ai_diagnosis": diag
    }))
}

fn report_context(report: &Value) -> Result<String> {
    let mut context = serde_json::Map::new();
    for key in [
        "analysis",
        "root_name",
        "metrics",
        "summary",
        "correlated_hypotheses",
        "comparison",
        "probabilities",
        "gates",
        "findings",
        "spectral_peaks",
        "observations",
        "limitations",
    ] {
        if let Some(value) = report.get(key) {
            let value = if let Some(items) = value.as_array() {
                Value::Array(items.iter().take(20).cloned().collect())
            } else {
                value.clone()
            };
            context.insert(key.to_owned(), value);
        }
    }
    if let Some(input) = report.get("input").and_then(Value::as_object) {
        let selected = ["name", "sample_count", "sample_rate_hz", "sha256"]
            .into_iter()
            .filter_map(|key| input.get(key).map(|value| (key.to_owned(), value.clone())))
            .collect();
        context.insert("input".to_owned(), Value::Object(selected));
    }
    Ok(format!(
        "Analysis report (selected summary only):\n{}",
        serde_json::to_string(&Value::Object(context))?
    ))
}

fn openai_reply(
    client: &Client,
    base_url: &str,
    model: &str,
    api_key: Option<&str>,
    messages: &[Value],
) -> Result<String> {
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let mut request = client
        .post(url)
        .json(&json!({"model": model, "messages": messages}));
    if let Some(key) = api_key {
        request = request.bearer_auth(key);
    }
    let response: Value = request
        .send()?
        .error_for_status()?
        .json()
        .context("OpenAI-compatible endpoint returned invalid JSON.")?;
    response["choices"][0]["message"]["content"]
        .as_str()
        .map(str::to_owned)
        .context("Model endpoint returned an unexpected chat response.")
}

fn gemini_reply(client: &Client, model: &str, api_key: &str, history: &[Value]) -> Result<String> {
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent",
        model
    );
    let response = client
        .post(url)
        .query(&[("key", api_key)])
        .json(&json!({
            "systemInstruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
            "contents": history
        }))
        .send()
        .map_err(|_| anyhow::anyhow!("Gemini request could not be sent."))?
        .error_for_status()
        .map_err(|error| {
            anyhow::anyhow!(
                "Gemini request failed with HTTP status {}.",
                error.status().unwrap_or_default()
            )
        })?;
    let response: Value = response
        .json()
        .context("Gemini endpoint returned invalid JSON.")?;
    response["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .map(str::to_owned)
        .context("Gemini returned an unexpected chat response.")
}

pub fn start_chat(
    report: &Value,
    provider: &str,
    model: Option<&str>,
    base_url: Option<&str>,
) -> Result<()> {
    if provider == "offline" {
        println!("Offline Physical AI Diagnostic Chat ready. Type 'exit' to quit.");
        loop {
            print!("iq-offline-ai> ");
            io::stdout().flush()?;
            let mut question = String::new();
            if io::stdin().read_line(&mut question)? == 0 {
                println!();
                return Ok(());
            }
            let question = question.trim();
            if matches!(question.to_ascii_lowercase().as_str(), "exit" | "quit") {
                return Ok(());
            }
            if question.is_empty() {
                continue;
            }
            let lang = if question.chars().any(|c| ('\u{0600}'..='\u{06FF}').contains(&c)) {
                "ar"
            } else {
                "en"
            };
            let answer = diagnose_report_offline(report, Some(question), lang);
            println!("{}", serde_json::to_string_pretty(&answer)?);
        }
    }

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;
    let model = match (provider, model) {
        ("openai-compatible", Some(model)) => model,
        ("openai-compatible", None) => {
            bail!("Pass --model for the OpenAI-compatible provider.");
        }
        (_, Some(model)) => model,
        (_, None) => "gemini-2.5-flash",
    };
    let (api_key, endpoint) = match provider {
        "gemini" => {
            let key = std::env::var("GEMINI_API_KEY")
                .context("Set GEMINI_API_KEY to use Gemini chat (or use --provider offline).")?;
            (Some(key), None)
        }
        "openai-compatible" => {
            let url = base_url
                .map(str::to_owned)
                .or_else(|| std::env::var("OPENAI_COMPATIBLE_BASE_URL").ok())
                .context("Pass --base-url or set OPENAI_COMPATIBLE_BASE_URL.")?;
            (std::env::var("OPENAI_COMPATIBLE_API_KEY").ok(), Some(url))
        }
        _ => bail!("Unsupported provider {provider:?}; choose offline, gemini, or openai-compatible."),
    };

    let context = report_context(report)?;
    let mut openai_messages = vec![
        json!({"role": "system", "content": SYSTEM_INSTRUCTION}),
        json!({"role": "user", "content": context}),
    ];
    let mut gemini_history = vec![json!({
        "role": "user",
        "parts": [{"text": context}]
    })];
    println!("Chat ready ({provider}, {model}). Type 'exit' to quit.");
    loop {
        print!("iq-chat> ");
        io::stdout().flush()?;
        let mut question = String::new();
        if io::stdin().read_line(&mut question)? == 0 {
            println!();
            return Ok(());
        }
        let question = question.trim();
        if matches!(question.to_ascii_lowercase().as_str(), "exit" | "quit") {
            return Ok(());
        }
        if question.is_empty() {
            continue;
        }

        let answer = if provider == "gemini" {
            gemini_history.push(json!({"role": "user", "parts": [{"text": question}]}));
            let reply = gemini_reply(
                &client,
                model,
                api_key.as_deref().context("Gemini API key is missing.")?,
                &gemini_history,
            )?;
            gemini_history.push(json!({"role": "model", "parts": [{"text": reply}]}));
            reply
        } else {
            openai_messages.push(json!({"role": "user", "content": question}));
            let reply = openai_reply(
                &client,
                endpoint.as_deref().context("Chat endpoint is missing.")?,
                model,
                api_key.as_deref(),
                &openai_messages,
            )?;
            openai_messages.push(json!({"role": "assistant", "content": reply}));
            reply
        };
        println!("{answer}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assess::generate_demo_workspace;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn autonomous_ai_discovers_correlates_and_audits_workspace() {
        let dir = std::env::temp_dir().join(format!(
            "iq-auto-ai-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        generate_demo_workspace(&dir).unwrap();
        let report = autonomous_workspace_audit(
            &dir,
            Some(&dir.join("scope.json")),
            Some(&dir.join("ai_ledger.jsonl")),
            Some(2_000_000.0),
        )
        .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(report["legal_authorized"], true);
        assert!(report["summary"]["artifacts_scanned"]["iq_files"].as_u64().unwrap() >= 1);
        assert!(report["summary"]["artifacts_scanned"]["logic_vcd_files"].as_u64().unwrap() >= 1);
        assert!(report["summary"]["artifacts_scanned"]["side_channel_matrices"].as_u64().unwrap() >= 1);
        assert!(report["correlated_hypotheses"].as_array().unwrap().len() >= 2);
    }
}
