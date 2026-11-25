use crate::common::sha256_file;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_FIRMWARE_BYTES: u64 = 128 * 1024 * 1024;

// ── YARA-lite pattern engine ──────────────────────────────────────────────────

/// A lightweight YARA-style byte-pattern rule (no regex, only literal/wildcard matching).
struct YaraRule {
    id: &'static str,
    severity: &'static str,
    description: &'static str,
    /// Byte pattern: `None` entries are single-byte wildcards (like `??` in YARA).
    pattern: &'static [Option<u8>],
}

const YARA_RULES: &[YaraRule] = &[
    YaraRule {
        id: "yara-jtag-openocd-banner",
        severity: "high",
        description: "OpenOCD/JTAG debug banner string found in firmware image",
        pattern: &[
            Some(b'O'), Some(b'p'), Some(b'e'), Some(b'n'), Some(b'O'), Some(b'C'), Some(b'D'),
        ],
    },
    YaraRule {
        id: "yara-busybox-applet-table",
        severity: "info",
        description: "BusyBox applet table detected — likely embedded Linux rootfs",
        pattern: &[
            Some(b'B'), Some(b'u'), Some(b's'), Some(b'y'), Some(b'B'), Some(b'o'), Some(b'x'),
        ],
    },
    YaraRule {
        id: "yara-dropbear-ssh-banner",
        severity: "medium",
        description: "Dropbear SSH server string detected — confirm access controls",
        pattern: &[
            Some(b'D'), Some(b'r'), Some(b'o'), Some(b'p'), Some(b'b'),
            Some(b'e'), Some(b'a'), Some(b'r'),
        ],
    },
    YaraRule {
        id: "yara-hard-aes-key-pattern",
        severity: "critical",
        description: "Possible AES-128 key-schedule constant (0x63 Rijndael S-box first byte at key boundary)",
        // Rijndael SubBytes S-box first row start: 63 7c 77 7b f2 6b 6f c5 30 01
        pattern: &[
            Some(0x63), Some(0x7c), Some(0x77), Some(0x7b), Some(0xf2),
            Some(0x6b), Some(0x6f), Some(0xc5), Some(0x30), Some(0x01),
        ],
    },
    YaraRule {
        id: "yara-linux-kernel-banner",
        severity: "info",
        description: "Linux kernel version banner embedded in firmware",
        pattern: &[
            Some(b'L'), Some(b'i'), Some(b'n'), Some(b'u'), Some(b'x'),
            Some(b' '), Some(b'v'), Some(b'e'), Some(b'r'), Some(b's'),
            Some(b'i'), Some(b'o'), Some(b'n'), Some(b' '),
        ],
    },
    YaraRule {
        id: "yara-pe-executable",
        severity: "medium",
        description: "Windows PE executable header embedded in firmware (MZ magic)",
        pattern: &[Some(b'M'), Some(b'Z')],
    },
    YaraRule {
        id: "yara-mqtt-cleartext",
        severity: "medium",
        description: "MQTT protocol identifier found — verify TLS is enforced",
        pattern: &[
            Some(0x00), Some(0x04), Some(b'M'), Some(b'Q'), Some(b'T'), Some(b'T'),
        ],
    },
];

fn yara_scan(data: &[u8]) -> Vec<Value> {
    let mut hits = Vec::new();
    for rule in YARA_RULES {
        let pat = rule.pattern;
        if pat.is_empty() || data.len() < pat.len() {
            continue;
        }
        let mut offset = 0_usize;
        let mut count = 0_usize;
        while offset + pat.len() <= data.len() {
            let matched = pat.iter().enumerate().all(|(i, byte)| {
                byte.map_or(true, |b| data[offset + i] == b)
            });
            if matched {
                hits.push(json!({
                    "rule_id": rule.id,
                    "severity": rule.severity,
                    "description": rule.description,
                    "offset": offset,
                    "offset_hex": format!("0x{offset:08x}")
                }));
                count += 1;
                if count >= 4 || hits.len() >= 32 {
                    break;
                }
            }
            offset += 1;
        }
        if hits.len() >= 32 {
            break;
        }
    }
    hits.sort_by_key(|h| h["offset"].as_u64().unwrap_or(0));
    hits
}

// ── Entropy delta analysis ────────────────────────────────────────────────────

/// Compute block entropies and find the maximum entropy *drop* between adjacent blocks.
/// A large drop from high→low entropy is a typical indicator of an encrypted+compressed
/// region transitioning into a plaintext config area — a useful structural marker.
fn entropy_delta_analysis(data: &[u8], block_size: usize) -> (f64, usize) {
    let entropies: Vec<f64> = data
        .chunks(block_size)
        .map(block_entropy)
        .collect();
    let mut max_drop = 0.0_f64;
    let mut max_drop_block = 0_usize;
    for i in 1..entropies.len() {
        let drop = entropies[i - 1] - entropies[i];
        if drop > max_drop {
            max_drop = drop;
            max_drop_block = i;
        }
    }
    (max_drop, max_drop_block)
}

// ── Magic signature scanner ───────────────────────────────────────────────────

struct MagicSig {
    name: &'static str,
    bytes: &'static [u8],
}

const MAGIC_SIGNATURES: &[MagicSig] = &[
    MagicSig { name: "ELF_Executable", bytes: b"\x7fELF" },
    MagicSig { name: "DeviceTree_FDT", bytes: &[0xd0, 0x0d, 0xfe, 0xed] },
    MagicSig { name: "Gzip_Stream", bytes: &[0x1f, 0x8b, 0x08] },
    MagicSig { name: "SquashFS_LE", bytes: b"hsqs" },
    MagicSig { name: "SquashFS_BE", bytes: b"sqsh" },
    MagicSig { name: "UBoot_uImage", bytes: &[0x27, 0x05, 0x19, 0x56] },
    MagicSig { name: "ZIP_Archive", bytes: b"PK\x03\x04" },
    MagicSig { name: "XZ_Stream", bytes: &[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
];

fn block_entropy(chunk: &[u8]) -> f64 {
    if chunk.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for &b in chunk {
        counts[b as usize] += 1;
    }
    let len = chunk.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn scan_magic_headers(data: &[u8]) -> Vec<Value> {
    let mut hits = Vec::new();
    for sig in MAGIC_SIGNATURES {
        if data.len() < sig.bytes.len() {
            continue;
        }
        let mut count = 0_usize;
        for (offset, win) in data.windows(sig.bytes.len()).enumerate() {
            if win == sig.bytes {
                hits.push(json!({
                    "signature": sig.name,
                    "offset": offset,
                    "offset_hex": format!("0x{offset:08x}")
                }));
                count += 1;
                if count >= 8 || hits.len() >= 32 {
                    break;
                }
            }
        }
        if hits.len() >= 32 {
            break;
        }
    }
    hits.sort_by_key(|h| h["offset"].as_u64().unwrap_or(0));
    hits
}

fn extract_ascii_indicators(data: &[u8]) -> (usize, Vec<Value>) {
    let mut strings_found = 0_usize;
    let mut indicators = Vec::new();
    let mut current = Vec::new();
    let mut start_offset = 0_usize;

    let mut check_string = |offset: usize, buf: &[u8]| {
        if buf.len() < 6 {
            return;
        }
        strings_found += 1;
        let text = String::from_utf8_lossy(buf);
        let lower = text.to_ascii_lowercase();
        let kind = if lower.contains("-----begin ") && lower.contains("private key") {
            Some(("critical", "embedded-private-key-header"))
        } else if lower.contains("telnetd") || lower.contains("uart_debug") || lower.contains("jtag_unlock") {
            Some(("high", "debug-or-legacy-service-string"))
        } else if lower.contains("http://") {
            Some(("medium", "cleartext-http-url"))
        } else if lower.contains("password=") || lower.contains("psk=") || lower.contains("api_key=") {
            Some(("high", "possible-embedded-credential-marker"))
        } else if lower.contains("busybox") || lower.contains("u-boot") || lower.contains("dropbear") {
            Some(("info", "firmware-component-banner"))
        } else {
            None
        };
        if let Some((severity, rule)) = kind
            && indicators.len() < 32
        {
            let redacted: String = text.chars().take(28).collect();
            indicators.push(json!({
                "rule_id": rule,
                "severity": severity,
                "offset": offset,
                "offset_hex": format!("0x{offset:08x}"),
                "excerpt": format!("{redacted}...")
            }));
        }
    };

    for (idx, &b) in data.iter().enumerate() {
        if (0x20..=0x7e).contains(&b) {
            if current.is_empty() {
                start_offset = idx;
            }
            if current.len() < 256 {
                current.push(b);
            }
        } else if !current.is_empty() {
            check_string(start_offset, &current);
            current.clear();
        }
    }
    if !current.is_empty() {
        check_string(start_offset, &current);
    }
    (strings_found, indicators)
}

/// Inspect a local hardware firmware binary / flash image (read-only).
pub fn inspect_firmware_binary(path: &Path) -> Result<Value> {
    let meta = path
        .metadata()
        .with_context(|| format!("Reading firmware metadata {}", path.display()))?;
    if !meta.is_file() {
        bail!("Firmware path is not a file: {}", path.display());
    }
    if meta.len() == 0 {
        bail!("Firmware binary is empty.");
    }
    if meta.len() > MAX_FIRMWARE_BYTES {
        bail!("Firmware binary exceeds the 128 MiB analysis limit.");
    }

    let data = fs::read(path).with_context(|| format!("Reading firmware {}", path.display()))?;
    let overall_entropy = block_entropy(&data);

    let block_size = (data.len() / 64).clamp(64, 4096);
    let mut high_entropy_blocks = 0_usize;
    let mut low_entropy_blocks = 0_usize;
    let mut entropy_profile = Vec::new();
    for (idx, chunk) in data.chunks(block_size).enumerate() {
        let e = block_entropy(chunk);
        if e >= 7.2 {
            high_entropy_blocks += 1;
        } else if e <= 2.0 {
            low_entropy_blocks += 1;
        }
        if entropy_profile.len() < 128 {
            entropy_profile.push([(idx * block_size) as f64, e]);
        }
    }
    let total_blocks = data.len().div_ceil(block_size).max(1);
    let high_entropy_fraction = high_entropy_blocks as f64 / total_blocks as f64;

    let signatures = scan_magic_headers(&data);
    let (string_count, indicators) = extract_ascii_indicators(&data);

    let mut by_severity: BTreeMap<&str, usize> = BTreeMap::new();
    let mut risk_score = 0_u32;
    for ind in &indicators {
        let sev = ind["severity"].as_str().unwrap_or("info");
        *by_severity.entry(sev).or_insert(0) += 1;
        risk_score = risk_score.saturating_add(match sev {
            "critical" => 30,
            "high" => 20,
            "medium" => 10,
            _ => 2,
        });
    }
    if high_entropy_fraction > 0.75 && signatures.is_empty() {
        risk_score = risk_score.saturating_add(15);
    }

    // ── YARA-lite pattern scan ───────────────────────────────────────────
    let yara_hits = yara_scan(&data);
    for hit in &yara_hits {
        let sev = hit["severity"].as_str().unwrap_or("info");
        risk_score = risk_score.saturating_add(match sev {
            "critical" => 25,
            "high" => 15,
            "medium" => 8,
            _ => 2,
        });
    }

    // ── Entropy delta analysis ───────────────────────────────────────────
    let (max_entropy_drop, max_drop_block) = entropy_delta_analysis(&data, block_size);
    if max_entropy_drop > 4.0 {
        risk_score = risk_score.saturating_add(10);
    }

    let observations = vec![
        format!(
            "Measured overall Shannon entropy {:.2} bits/byte across {} bytes ({:.1}% high-entropy blocks).",
            overall_entropy,
            data.len(),
            high_entropy_fraction * 100.0
        ),
        format!(
            "Detected {} embedded format signature(s) and {} printable ASCII string(s) ({} security indicator(s)).",
            signatures.len(),
            string_count,
            indicators.len()
        ),
        format!(
            "YARA-lite engine matched {} rule(s). Max inter-block entropy drop: {:.2} bits/byte at block index {}.",
            yara_hits.len(),
            max_entropy_drop,
            max_drop_block
        ),
    ];

    Ok(json!({
        "schema_version": 2,
        "analysis": "offline_firmware_binary_surface_review",
        "input": {
            "name": path.file_name().unwrap_or_default().to_string_lossy(),
            "size_bytes": data.len(),
            "sha256": sha256_file(path)?
        },
        "metrics": {
            "overall_entropy_bits_per_byte": overall_entropy,
            "high_entropy_block_fraction": high_entropy_fraction,
            "low_entropy_block_count": low_entropy_blocks,
            "signature_count": signatures.len(),
            "printable_string_count": string_count,
            "indicator_count": indicators.len(),
            "yara_hit_count": yara_hits.len(),
            "max_entropy_drop_bits": max_entropy_drop,
            "max_entropy_drop_block": max_drop_block,
            "by_severity": by_severity,
            "risk_score": risk_score.min(100)
        },
        "signatures": signatures,
        "indicators": indicators,
        "yara_hits": yara_hits,
        "preview": {
            "entropy_profile": entropy_profile
        },
        "observations": observations,
        "limitations": [
            "Read-only surface triage only; no disassembly, unpacking, or code execution is performed.",
            "High entropy blocks may indicate compressed assets rather than encryption.",
            "String excerpts are truncated and require authorized reverse-engineering verification.",
            "YARA-lite patterns use literal byte matching only; no regex or complex conditions."
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn inspects_magic_headers_entropy_and_indicators() {
        let path = std::env::temp_dir().join(format!(
            "iq-fw-{}-{}.bin",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0xd0, 0x0d, 0xfe, 0xed]); // FDT magic
        blob.extend_from_slice(b"U-Boot 2026.01 UART_DEBUG_CONSOLE http://device.local BusyBox v1.36 ");
        blob.extend((0..256).map(|i| ((i * 73 + 19) % 256) as u8));
        fs::write(&path, &blob).unwrap();

        let report = inspect_firmware_binary(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(report["schema_version"], 2);
        assert!(report["metrics"]["signature_count"].as_u64().unwrap() >= 1);
        assert!(report["metrics"]["indicator_count"].as_u64().unwrap() >= 2);
        assert!(report["metrics"]["risk_score"].as_u64().unwrap() >= 30);
        assert!(report["metrics"]["yara_hit_count"].as_u64().unwrap() >= 1);
        assert!(report["metrics"].get("max_entropy_drop_bits").is_some());
    }

    #[test]
    fn yara_lite_matches_busybox_and_dropbear() {
        let path = std::env::temp_dir().join(format!(
            "iq-fw-yara-{}-{}.bin",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        let mut blob = vec![0u8; 64];
        blob.extend_from_slice(b"BusyBox applets Dropbear SSH server");
        blob.extend(vec![0x55u8; 128]);
        fs::write(&path, &blob).unwrap();
        let report = inspect_firmware_binary(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(report["metrics"]["yara_hit_count"].as_u64().unwrap() >= 2);
    }
}
