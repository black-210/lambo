//! # Protocol Analyzer Module
//!
//! Offline network packet & telemetry capture analyzer supporting BOTH:
//! - Standard **binary `.pcap` packet captures** (from scratch parser: Ethernet II / IPv4 / TCP / UDP)
//! - Structured **`.csv` packet captures**
//!
//! Surfaces cleartext protocols, sensitive payload strings, DNS exfiltration heuristics,
//! periodic C2 beaconing intervals, port scans, and anomalous ephemeral-port payloads.

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;

/// A parsed packet record normalized from `.pcap` or `.csv`.
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: f64,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,
    pub payload_hex: String,
}

fn parse_csv_capture(path: &Path) -> Result<Vec<Packet>> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Opening protocol capture {}", path.display()))?;

    let mut packets: Vec<Packet> = Vec::new();
    for result in reader.records() {
        let record = result?;
        if record.len() < 7 {
            continue;
        }
        packets.push(Packet {
            timestamp: record.get(0).unwrap_or("0").parse().unwrap_or(0.0),
            src_ip: record.get(1).unwrap_or("").to_owned(),
            dst_ip: record.get(2).unwrap_or("").to_owned(),
            protocol: record.get(3).unwrap_or("").to_uppercase(),
            src_port: record.get(4).unwrap_or("0").parse().unwrap_or(0),
            dst_port: record.get(5).unwrap_or("0").parse().unwrap_or(0),
            length: record.get(6).unwrap_or("0").parse().unwrap_or(0),
            payload_hex: record.get(7).unwrap_or("").to_owned(),
        });
    }
    Ok(packets)
}

/// From-scratch binary `.pcap` parser (Ethernet II + IPv4 + TCP/UDP).
fn parse_pcap_binary(bytes: &[u8]) -> Result<Vec<Packet>> {
    if bytes.len() < 24 {
        bail!("PCAP file shorter than 24-byte global header.");
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (little_endian, nano_ts) = match magic {
        0xa1b2_c3d4 => (true, false),
        0xd4c3_b2a1 => (false, false),
        0xa1b2_3c4d => (true, true),
        0x4d3c_b2a1 => (false, true),
        _ => bail!("Unsupported PCAP magic header 0x{magic:08x}"),
    };
    let read_u32 = |off: usize| -> u32 {
        let b = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    };

    let linktype = read_u32(20);
    let mut offset = 24usize;
    let mut packets = Vec::new();

    while offset + 16 <= bytes.len() && packets.len() < 200_000 {
        let ts_sec = read_u32(offset) as f64;
        let ts_sub = read_u32(offset + 4) as f64;
        let incl_len = read_u32(offset + 8) as usize;
        let orig_len = read_u32(offset + 12) as usize;
        offset += 16;
        if offset + incl_len > bytes.len() {
            break;
        }
        let frame = &bytes[offset..offset + incl_len];
        offset += incl_len;
        let timestamp = ts_sec + ts_sub / if nano_ts { 1e9 } else { 1e6 };

        // Decode Ethernet II -> IPv4 when linktype == 1 (Ethernet)
        let ip_slice = if linktype == 1 && frame.len() >= 14 {
            let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            if ethertype == 0x0800 {
                &frame[14..]
            } else if ethertype == 0x8100 && frame.len() >= 18 {
                &frame[18..]
            } else {
                &[][..]
            }
        } else if linktype == 101 {
            frame
        } else {
            &[][..]
        };

        if ip_slice.len() >= 20 && (ip_slice[0] >> 4) == 4 {
            let ihl = ((ip_slice[0] & 0x0f) as usize) * 4;
            if ihl >= 20 && ip_slice.len() >= ihl {
                let proto_num = ip_slice[9];
                let src_ip = format!(
                    "{}.{}.{}.{}",
                    ip_slice[12], ip_slice[13], ip_slice[14], ip_slice[15]
                );
                let dst_ip = format!(
                    "{}.{}.{}.{}",
                    ip_slice[16], ip_slice[17], ip_slice[18], ip_slice[19]
                );
                let l4 = &ip_slice[ihl..];
                let (protocol, src_port, dst_port, payload) = match proto_num {
                    6 if l4.len() >= 20 => {
                        let sp = u16::from_be_bytes([l4[0], l4[1]]);
                        let dp = u16::from_be_bytes([l4[2], l4[3]]);
                        let doff = ((l4[12] >> 4) as usize) * 4;
                        let pl = if doff >= 20 && l4.len() >= doff {
                            &l4[doff..]
                        } else {
                            &[][..]
                        };
                        ("TCP".to_owned(), sp, dp, pl)
                    }
                    17 if l4.len() >= 8 => {
                        let sp = u16::from_be_bytes([l4[0], l4[1]]);
                        let dp = u16::from_be_bytes([l4[2], l4[3]]);
                        ("UDP".to_owned(), sp, dp, &l4[8..])
                    }
                    1 => ("ICMP".to_owned(), 0, 0, l4),
                    other => (format!("IP_{other}"), 0, 0, l4),
                };

                let preview = &payload[..payload.len().min(256)];
                packets.push(Packet {
                    timestamp,
                    src_ip,
                    dst_ip,
                    protocol,
                    src_port,
                    dst_port,
                    length: orig_len,
                    payload_hex: hex::encode(preview),
                });
            }
        }
    }

    Ok(packets)
}

/// Analyze a protocol capture file (`.pcap` binary or `.csv`).
pub fn analyze_protocol_capture(path: &Path) -> Result<Value> {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    let (packets, container) = if ext == "pcap" {
        let bytes =
            std::fs::read(path).with_context(|| format!("Reading PCAP {}", path.display()))?;
        (parse_pcap_binary(&bytes)?, "pcap_binary")
    } else {
        (parse_csv_capture(path)?, "csv_capture")
    };

    if packets.is_empty() {
        return Ok(json!({
            "analysis": "protocol_capture",
            "container": container,
            "status": "empty_capture",
            "note": "No packets found in the capture file."
        }));
    }

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

    let mut top_ports: Vec<_> = port_counts.into_iter().collect();
    top_ports.sort_by_key(|a| std::cmp::Reverse(a.1));
    top_ports.truncate(10);

    let mut top_pairs: Vec<_> = ip_pair_counts.into_iter().collect();
    top_pairs.sort_by_key(|a| std::cmp::Reverse(a.1));
    top_pairs.truncate(10);

    let anomalies = detect_anomalies(&packets);

    let duration = if packets.len() >= 2 {
        (packets.last().unwrap().timestamp - packets.first().unwrap().timestamp).max(0.0)
    } else {
        0.0
    };
    let pps = if duration > 0.0 {
        total as f64 / duration
    } else {
        0.0
    };

    Ok(json!({
        "schema_version": 2,
        "analysis": "protocol_capture",
        "container": container,
        "file": path.display().to_string(),
        "statistics": {
            "total_packets": total,
            "total_bytes": total_bytes,
            "duration_seconds": duration,
            "packets_per_second": pps,
            "protocols": proto_counts,
            "top_destination_ports": top_ports
                .iter()
                .map(|(port, count)| json!({"port": port, "count": count}))
                .collect::<Vec<_>>(),
            "top_ip_pairs": top_pairs
                .iter()
                .map(|(pair, count)| json!({"pair": pair, "count": count}))
                .collect::<Vec<_>>()
        },
        "anomaly_count": anomalies.as_array().map_or(0, Vec::len),
        "anomalies": anomalies
    }))
}

/// Detect protocol, timing, port-sweep, and payload anomalies in a packet slice.
pub fn detect_anomalies(packets: &[Packet]) -> Value {
    let mut findings: Vec<Value> = Vec::new();

    // 1. Cleartext legacy / IoT protocols
    let cleartext_ports: HashMap<u16, &str> = HashMap::from([
        (21, "FTP"),
        (23, "Telnet"),
        (69, "TFTP"),
        (80, "HTTP"),
        (161, "SNMP"),
        (502, "Modbus-TCP"),
        (1883, "MQTT-Cleartext"),
    ]);
    let mut seen_protos = BTreeSet::new();
    for pkt in packets {
        if let Some(&proto) = cleartext_ports.get(&pkt.dst_port)
            && seen_protos.insert(proto)
        {
            findings.push(json!({
                "type": "cleartext_protocol",
                "severity": "high",
                "timestamp": pkt.timestamp,
                "detail": format!("{proto} traffic detected ({} -> {}:{})", pkt.src_ip, pkt.dst_ip, pkt.dst_port)
            }));
        }
    }

    // 2. Suspicious ephemeral high ports (>49152) with substantial payloads
    let suspicious_high: Vec<_> = packets
        .iter()
        .filter(|p| p.dst_port > 49152 && p.length > 500)
        .collect();
    if !suspicious_high.is_empty() {
        findings.push(json!({
            "type": "suspicious_high_port",
            "severity": "medium",
            "count": suspicious_high.len(),
            "detail": format!("{} packets to ephemeral ports (>49152) with payload >500 bytes", suspicious_high.len())
        }));
    }

    // 3. DNS exfiltration heuristic
    let dns_large: Vec<_> = packets
        .iter()
        .filter(|p| (p.dst_port == 53 || p.src_port == 53) && p.length > 200)
        .collect();
    if !dns_large.is_empty() {
        findings.push(json!({
            "type": "dns_exfiltration_candidate",
            "severity": "high",
            "count": dns_large.len(),
            "detail": format!("{} DNS packets with unusually large payloads (>200 bytes)", dns_large.len())
        }));
    }

    // 4. Periodic Beaconing Detector (low jitter coefficient of variation in inter-arrival times)
    let mut flow_times: HashMap<(String, String, u16), Vec<f64>> = HashMap::new();
    for p in packets {
        flow_times
            .entry((p.src_ip.clone(), p.dst_ip.clone(), p.dst_port))
            .or_default()
            .push(p.timestamp);
    }
    for ((src, dst, port), ts) in flow_times {
        if ts.len() >= 5 {
            let iats: Vec<f64> = ts.windows(2).map(|w| (w[1] - w[0]).abs()).collect();
            let mean_iat = iats.iter().sum::<f64>() / iats.len() as f64;
            if mean_iat > 0.05 {
                let var = iats.iter().map(|x| (x - mean_iat).powi(2)).sum::<f64>() / iats.len() as f64;
                let cv = var.sqrt() / mean_iat;
                if cv < 0.15 {
                    findings.push(json!({
                        "type": "periodic_beaconing_pattern",
                        "severity": "medium",
                        "flow": format!("{src} -> {dst}:{port}"),
                        "period_seconds": mean_iat,
                        "jitter_cv": cv,
                        "detail": format!("Regular periodic traffic every {mean_iat:.2}s (CV={cv:.3})")
                    }));
                }
            }
        }
    }

    // 5. Port scan / sweep detector per source IP
    let mut src_ports_touched: HashMap<String, BTreeSet<u16>> = HashMap::new();
    for p in packets {
        if p.dst_port > 0 {
            src_ports_touched
                .entry(p.src_ip.clone())
                .or_default()
                .insert(p.dst_port);
        }
    }
    for (src, ports) in src_ports_touched {
        if ports.len() >= 10 {
            findings.push(json!({
                "type": "port_sweep_activity",
                "severity": "medium",
                "source_ip": src,
                "unique_dst_ports": ports.len(),
                "detail": format!("Source {src} contacted {} distinct destination ports", ports.len())
            }));
        }
    }

    // 6. Sensitive keywords in hex payloads
    let sensitive_patterns = [
        ("password", "70617373776f7264"),
        ("login", "6c6f67696e"),
        ("api_key", "6170695f6b6579"),
    ];
    for pkt in packets {
        let payload_lower = pkt.payload_hex.to_ascii_lowercase();
        for (label, pat) in &sensitive_patterns {
            if payload_lower.contains(pat) {
                findings.push(json!({
                    "type": "sensitive_keyword_in_payload",
                    "severity": "critical",
                    "timestamp": pkt.timestamp,
                    "detail": format!("Keyword '{label}' found in packet {} -> {}:{}", pkt.src_ip, pkt.dst_ip, pkt.dst_port)
                }));
            }
        }
    }

    json!(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn parse_and_analyze_csv() {
        let dir = std::env::temp_dir().join(format!("iq_proto_csv_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv_path = dir.join("capture.csv");

        let mut f = std::fs::File::create(&csv_path).unwrap();
        writeln!(f, "timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length,payload_hex").unwrap();
        writeln!(f, "0.0,192.168.1.1,10.0.0.1,TCP,12345,80,100,48454c4c4f").unwrap();
        writeln!(f, "0.1,192.168.1.1,10.0.0.1,TCP,12345,80,200,").unwrap();
        writeln!(f, "0.2,10.0.0.1,192.168.1.1,TCP,80,12345,150,").unwrap();

        let res = analyze_protocol_capture(&csv_path).unwrap();
        assert_eq!(res["statistics"]["total_packets"], 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parses_synthetic_binary_pcap() {
        let dir = std::env::temp_dir().join(format!("iq_proto_pcap_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pcap_path = dir.join("trace.pcap");

        // Build Ethernet(14) + IPv4(20) + UDP(8) + "password"(8) = 50 bytes targeting port 1883 (MQTT)
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xffu8; 6]); // dst mac
        frame.extend_from_slice(&[0x01u8; 6]); // src mac
        frame.extend_from_slice(&[0x08, 0x00]); // IPv4
        frame.extend_from_slice(&[0x45, 0x00, 0x00, 36, 0x00, 0x01, 0x00, 0x00, 64, 17, 0, 0]);
        frame.extend_from_slice(&[192, 168, 1, 10]); // src
        frame.extend_from_slice(&[192, 168, 1, 20]); // dst
        frame.extend_from_slice(&12345u16.to_be_bytes());
        frame.extend_from_slice(&1883u16.to_be_bytes());
        frame.extend_from_slice(&16u16.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(b"password");

        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

        pcap.extend_from_slice(&1000u32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&frame);

        std::fs::write(&pcap_path, pcap).unwrap();
        let rep = analyze_protocol_capture(&pcap_path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(rep["container"], "pcap_binary");
        assert_eq!(rep["statistics"]["total_packets"], 1);
        assert!(rep["anomaly_count"].as_u64().unwrap() >= 2);
        assert!(rep["anomalies"]["mqtt_password_in_clear_text"].as_bool().unwrap());
        assert!(rep["anomalies"]["mqtt_password_in_clear_text"]["evidence"].as_array().unwrap().len() >= 1);
        let json_path = pcap_path.with_extension("json");
        json_path;
        
        if let Ok(entry) = std::fs::read_dir(&dir) {
            for entry in entry {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_file() {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }
}
