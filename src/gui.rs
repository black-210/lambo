use crate::assess::{
    AssessmentInput, assess_engagement, export_html_report, export_markdown_report,
    export_sarif_report, generate_demo_workspace,
};
use crate::audit::scan_source_tree;
use crate::evidence::{create_manifest, verify_manifest};
use crate::legal::verify_audit_ledger;
use crate::physical::analyze_trace;
use crate::quantum::simulate_qubit;
use crate::signal::analyze_iq;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

const WORKBENCH_HTML: &str = include_str!("assets/workbench.html");
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn json_response(stream: &mut TcpStream, status: &str, value: &Value) -> Result<()> {
    let body = serde_json::to_vec(value)?;
    write_http_response(stream, status, "application/json; charset=utf-8", &body)
}

fn req_path(body: &Value, key: &str) -> Result<PathBuf> {
    let raw = body[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .with_context(|| format!("Missing required field '{key}'."))?;
    Ok(PathBuf::from(raw))
}

fn opt_path(body: &Value, key: &str) -> Option<PathBuf> {
    body[key]
        .as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

pub fn handle_api(path: &str, body: Value) -> Result<Value> {
    match path {
        "/api/sample" => {
            let dir = opt_path(&body, "output_dir").unwrap_or_else(|| PathBuf::from("./demo_lab"));
            generate_demo_workspace(&dir)
        }
        "/api/analyze-iq" => {
            let iq_file = req_path(&body, "iq_file")?;
            let rate = body["sample_rate_hz"].as_f64();
            analyze_iq(&iq_file, rate)
        }
        "/api/analyze-physical" => {
            let trace = req_path(&body, "trace")?;
            let reference = opt_path(&body, "reference");
            let threshold = body["threshold"].as_f64().unwrap_or(6.0);
            analyze_trace(&trace, reference.as_deref(), threshold)
        }
        "/api/audit" => {
            let root = req_path(&body, "root")?;
            scan_source_tree(&root)
        }
        "/api/assess" => {
            let input = AssessmentInput {
                iq_file: opt_path(&body, "iq_file"),
                sample_rate_hz: body["sample_rate_hz"].as_f64(),
                physical_trace: opt_path(&body, "physical_trace"),
                physical_reference: opt_path(&body, "physical_reference"),
                physical_threshold: body["threshold"].as_f64().unwrap_or(6.0),
                source_dir: opt_path(&body, "source_dir"),
                scope_file: opt_path(&body, "scope_file"),
                ledger_file: opt_path(&body, "ledger_file"),
            };
            assess_engagement(&input)
        }
        "/api/export-html" => {
            let out = req_path(&body, "output_path")?;
            let report = body
                .get("report")
                .context("Missing 'report' JSON object.")?;
            export_html_report(report, &out)?;
            Ok(json!({ "exported": true, "output_path": out.to_string_lossy() }))
        }
        "/api/export-markdown" => {
            let out = req_path(&body, "output_path")?;
            let report = body
                .get("report")
                .context("Missing 'report' JSON object.")?;
            export_markdown_report(report, &out)?;
            Ok(json!({ "exported": true, "output_path": out.to_string_lossy() }))
        }
        "/api/export-sarif" => {
            let out = req_path(&body, "output_path")?;
            let report = body
                .get("report")
                .context("Missing 'report' JSON object.")?;
            export_sarif_report(report, &out)?;
            Ok(json!({ "exported": true, "output_path": out.to_string_lossy() }))
        }
        "/api/forensic/inventory" => {
            let root = req_path(&body, "root")?;
            let out = opt_path(&body, "output");
            let manifest = create_manifest(&root)?;
            if let Some(out_path) = out {
                let canon_root = root.canonicalize().unwrap_or(root);
                let abs_out = out_path
                    .canonicalize()
                    .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default().join(&out_path));
                if abs_out.starts_with(&canon_root) {
                    bail!("Keep the evidence manifest outside the evidence directory.");
                }
                fs::write(&out_path, serde_json::to_string_pretty(&manifest)?)?;
            }
            Ok(manifest)
        }
        "/api/forensic/verify" => {
            let root = req_path(&body, "root")?;
            let manifest = req_path(&body, "manifest")?;
            verify_manifest(&root, &manifest)
        }
        "/api/ledger/verify" => {
            let ledger = req_path(&body, "ledger")?;
            verify_audit_ledger(&ledger)
        }
        "/api/quantum" => {
            let gates_raw = body["gates"].as_str().unwrap_or("");
            let gates: Vec<String> = gates_raw
                .split(',')
                .map(str::trim)
                .filter(|g| !g.is_empty())
                .map(str::to_owned)
                .collect();
            let theta = body["theta"].as_f64().unwrap_or(0.0);
            let phi = body["phi"].as_f64().unwrap_or(0.0);
            simulate_qubit(&gates, theta, phi)
        }
        _ => bail!("Unknown API endpoint: {path}"),
    }
}

pub fn handle_connection(mut stream: TcpStream) {
    let Ok(cloned) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(cloned);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1].split('?').next().unwrap_or("/");

    let mut content_length = 0_usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("content-length:") {
            content_length = rest.trim().parse().unwrap_or(0);
        }
    }

    if method == "GET" && (path == "/" || path == "/index.html") {
        let _ = write_http_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            WORKBENCH_HTML.as_bytes(),
        );
        return;
    }

    if method == "GET" && path == "/api/health" {
        let _ = json_response(&mut stream, "200 OK", &json!({"status": "ok"}));
        return;
    }

    if method == "POST" && path.starts_with("/api/") {
        if content_length > MAX_BODY_BYTES {
            let _ = json_response(
                &mut stream,
                "413 Payload Too Large",
                &json!({"error": "Request body too large."}),
            );
            return;
        }
        let mut buf = vec![0_u8; content_length];
        if content_length > 0 && reader.read_exact(&mut buf).is_err() {
            let _ = json_response(
                &mut stream,
                "400 Bad Request",
                &json!({"error": "Failed to read request body."}),
            );
            return;
        }
        let parsed: Value = if buf.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&buf) {
                Ok(v) => v,
                Err(e) => {
                    let _ = json_response(
                        &mut stream,
                        "400 Bad Request",
                        &json!({"error": format!("Invalid JSON: {e}")}),
                    );
                    return;
                }
            }
        };

        match handle_api(path, parsed) {
            Ok(val) => {
                let _ = json_response(&mut stream, "200 OK", &val);
            }
            Err(err) => {
                let _ = json_response(
                    &mut stream,
                    "400 Bad Request",
                    &json!({"error": format!("{err:#}")}),
                );
            }
        }
        return;
    }

    let _ = write_http_response(
        &mut stream,
        "404 Not Found",
        "text/plain; charset=utf-8",
        b"Not Found",
    );
}

pub fn launch_gui(port: u16, open_in_browser: bool) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("Binding local GUI server on 127.0.0.1:{port}"))?;
    let local_addr = listener.local_addr()?;
    let url = format!("http://{local_addr}/");
    println!("IQ Hardware Red-Team Workbench GUI listening at {url}");
    println!("Bound strictly to 127.0.0.1 (offline local mode). Press Ctrl+C to stop.");
    if open_in_browser {
        open_browser(&url);
    }
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || handle_connection(stream));
            }
            Err(err) => eprintln!("GUI connection error: {err}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_and_quantum_api_work() {
        let out = handle_api("/api/quantum", json!({"gates": "H", "theta": 0.0, "phi": 0.0})).unwrap();
        assert!((out["probabilities"]["0"].as_f64().unwrap() - 0.5).abs() < 1e-12);
        assert!(std::path::Path::new("src/assets/workbench.html").exists());
    }
}
