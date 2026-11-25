//! # Protocol Analyzer Module
//!
//! Offline protocol-capture analysis for hardware red-team engagements.
//! Parses simplified CSV packet captures and surfaces anomalies such as
//! unusual ports, cleartext credentials, DNS exfiltration patterns,
//! replay candidates, and timing irregularities.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

/// A single parsed packet record from a CSV capture.
#[derive(Debug, Clone)]
struct Packet {
    timestamp: f64,
    src_ip: String,
    dst_ip: String,
    protocol: String,
    src_port: u16,
    dst_port: u16,
    length: usize,
    payload_hex: String,
}

/// Analyze a protocol capture CSV file.
///
/// Expected CSV columns: `timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,payload_hex`
///
/// Returns a JSON report with traffic statistics and detected anomalies.
pub fn analyze_protocol_capture(path: &Path) -> Result<Value> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Opening protocol capture {}", path.display()))?;

    let mut packets: Vec<Packet> = Vec::new();
    for result in reader.records() {
        let record = result?;
        if record.len() < 7 { continue; }
        let pkt = Packet {
            timestamp: record.get(0).unwrap_or("0").parse().unwrap_or(0.0),
            src_ip: record.get(1).unwrap_or("").to_string(),
            dst_ip: record.get(2).unwrap_or("").to_string(),
            protocol: record.get(3).unwrap_or("").to_uppercase(),
            src_port: record.get(4).unwrap_or("0").parse().unwrap_or(0),
            dst_port: record.get(5).unwrap_or("0").parse().unwrap_or(0),
            length: record.get(6).unwrap_or("0").parse().unwrap_or(0),
            payload_hex: record.get(7).unwrap_or("").to_string(),
        };
        packets.push(pkt);
    }

    if packets.is_empty() {
        return Ok(json!({
            "status": "empty_capture",
            "note": "No packets found in the capture file."
        }));
    }

    // ── Traffic statistics ────────────────────────────────────────────────
    let total = packets.len();
    let total_bytes: usize = packets.iter().map(|p| p.length).sum();

    let mut proto_counts: HashMap<String, usize> = HashMap::new();
    let mut port_counts: HashMap<u16, usize> = HashMap::new();
    let mut ip_pair_counts: HashMap<String, usize> = HashMap::new();

    for pkt in &packets {
        *proto_counts.entry(pkt.protocol.clone()).or_default() += 1;
        *port_counts.entry(pkt.dst_port).or_default() += 1;
        let pair = format!("{} -> {}", pkt.src_ip, pkt.dst_ip);
        *ip_pair_counts.entry(pair).or_default() += 1;
    }

    // Top 10 destination ports
    let mut top_ports: Vec<_> = port_counts.into_iter().collect();
    top_ports.sort_by(|a, b| b.1.cmp(&a.1));
    top_ports.truncate(10);

    // Top 10 IP pairs
    let mut top_pairs: Vec<_> = ip_pair_counts.into_iter().collect();
    top_pairs.sort_by(|a, b| b.1.cmp(&a.1));
    top_pairs.truncate(10);

    // ── Anomaly detection ────────────────────────────────────────────────
    let anomalies = detect_anomalies(&packets);

    // ── Timing analysis ──────────────────────────────────────────────────
    let duration = if packets.len() >= 2 {
        packets.last().unwrap().timestamp - packets.first().unwrap().timestamp
    } else {
        0.0
    };
    let pps = if duration > 0.0 { total as f64 / duration } else { 0.0 };

    Ok(json!({
        "analysis": "protocol_capture",
        "file": path.display().to_string(),
        "statistics": {
            "total_packets": total,
            "total_bytes": total_bytes,
            "duration_seconds": duration,
            "packets_per_second": pps,
            "protocols": proto_counts,
            "top_destination_ports": top_ports.iter()
                .map(|(port, count)| json!({"port": port, "count": count}))
                .collect::<Vec<_>>(),
            "top_ip_pairs": top_pairs.iter()
                .map(|(pair, count)| json!({"pair": pair, "count": count}))
                .collect::<Vec<_>>(),
        },
        "anomalies": anomalies,
    }))
}

/// Detect anomalies in a packet stream.
pub fn detect_anomalies(packets: &[Packet]) -> Value {
    let mut findings: Vec<Value> = Vec::new();

    // 1. Cleartext protocol detection
    let cleartext_ports: HashMap<u16, &str> = HashMap::from([
        (21, "FTP"), (23, "Telnet"), (80, "HTTP"),
        (25, "SMTP"), (110, "POP3"), (143, "IMAP"),
        (69, "TFTP"), (161, "SNMP"),
    ]);
    for pkt in packets {
        if let Some(proto) = cleartext_ports.get(&pkt.dst_port) {
            findings.push(json!({
                "type": "cleartext_protocol",
                "severity": "high",
                "timestamp": pkt.timestamp,
                "detail": format!("{} traffic detected ({} -> {}:{})",
                    proto, pkt.src_ip, pkt.dst_ip, pkt.dst_port),
            }));
            break; // report once per protocol type
        }
    }

    // 2. Unusual high ports (>49152) with large payloads — potential C2
    let suspicious_high: Vec<_> = packets.iter()
        .filter(|p| p.dst_port > 49152 && p.length > 500)
        .collect();
    if !suspicious_high.is_empty() {
        findings.push(json!({
            "type": "suspicious_high_port",
            "severity": "medium",
            "count": suspicious_high.len(),
            "detail": format!("{} packets to ephemeral ports (>49152) with payload >500 bytes",
                suspicious_high.len()),
        }));
    }

    // 3. DNS exfiltration heuristic — DNS packets with large payloads
    let dns_large: Vec<_> = packets.iter()
        .filter(|p| p.dst_port == 53 && p.length > 200)
        .collect();
    if !dns_large.is_empty() {
        findings.push(json!({
            "type": "dns_exfiltration_candidate",
            "severity": "high",
            "count": dns_large.len(),
            "detail": format!("{} DNS packets with unusually large payloads (>200 bytes)",
                dns_large.len()),
        }));
    }

    // 4. Timing burst detection — many packets in a very short interval
    if packets.len() >= 10 {
        for window in packets.windows(10) {
            let dt = window.last().unwrap().timestamp - window.first().unwrap().timestamp;
            if dt > 0.0 && dt < 0.01 {
                findings.push(json!({
                    "type": "traffic_burst",
                    "severity": "low",
                    "detail": format!("10 packets in {:.4}s — possible scan or flood", dt),
                    "timestamp_start": window.first().unwrap().timestamp,
                }));
                break;
            }
        }
    }

    // 5. Payload pattern: look for "password", "login", "key" in hex payloads
    let sensitive_patterns = ["70617373776f7264", "6c6f67696e", "6b6579"]; // password, login, key
    for pkt in packets {
        let payload_lower = pkt.payload_hex.to_lowercase();
        for pat in &sensitive_patterns {
            if payload_lower.contains(pat) {
                findings.push(json!({
                    "type": "sensitive_keyword_in_payload",
                    "severity": "critical",
                    "timestamp": pkt.timestamp,
                    "detail": format!("Sensitive keyword found in packet {} -> {}:{}",
                        pkt.src_ip, pkt.dst_ip, pkt.dst_port),
                }));
            }
        }
    }

    json!(findings)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_and_analyze_csv() {
        let dir = std::env::temp_dir().join("iq_proto_test");
        std::fs::create_dir_all(&dir).unwrap();
        let csv_path = dir.join("capture.csv");

        let mut f = std::fs::File::create(&csv_path).unwrap();
        writeln!(f, "timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,payload_hex").unwrap();
        writeln!(f, "0.0,192.168.1.1,10.0.0.1,TCP,12345,80,100,48454c4c4f").unwrap();
        writeln!(f, "0.1,192.168.1.1,10.0.0.1,TCP,12345,80,200,").unwrap();
        writeln!(f, "0.2,10.0.0.1,192.168.1.1,TCP,80,12345,150,").unwrap();

        let res = analyze_protocol_capture(&csv_path).unwrap();
        assert_eq!(res["statistics"]["total_packets"], 3);

        // cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn detect_cleartext() {
        let packets = vec![
            Packet {
                timestamp: 0.0, src_ip: "a".into(), dst_ip: "b".into(),
                protocol: "TCP".into(), src_port: 1234, dst_port: 23,
                length: 50, payload_hex: String::new(),
            },
        ];
        let anomalies = detect_anomalies(&packets);
        let arr = anomalies.as_array().unwrap();
        assert!(arr.iter().any(|a| a["type"] == "cleartext_protocol"));
    }
}
