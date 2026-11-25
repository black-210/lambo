use crate::common::sha256_file;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_FIRMWARE_BYTES: u64 = 128 * 1024 * 1024;

// ── YARA-lite pattern engine ──────────────────────────────────────────────────

struct YaraRule {
    id: &'static str,
    severity: &'static str,
    description: &'static str,
    pattern: &'static [Option<u8>],
}

const LINUX_KERNEL_PAT: &[Option<u8>] = &[
    Some(b'L'), Some(b'i'), Some(b'n'), Some(b'u'), Some(b'x'),
    Some(b' '), Some(b'v'), Some(b'e'), Some(b'r'), Some(b's'),
    Some(b'i'), Some(b'o'), Some(b'n'), Some(b' '),
];

const OPENSSH_PAT: &[Option<u8>] = &[
    Some(b'B'), Some(b'E'), Some(b'G'), Some(b'I'), Some(b'N'), Some(b' '),
    Some(b'O'), Some(b'P'), Some(b'E'), Some(b'N'), Some(b'S'), Some(b'S'), Some(b'H'),
    Some(b' '), Some(b'P'), Some(b'R'), Some(b'I'), Some(b'V'), Some(b'A'), Some(b'T'), Some(b'E'),
    Some(b' '), Some(b'K'), Some(b'E'), Some(b'Y'),
];

const EXTRA_YARA_RULES: &[YaraRule] = &[
    YaraRule {
        id: "yara-linux-kernel-banner",
        severity: "info",
        description: "Linux kernel version banner embedded in firmware",
        pattern: LINUX_KERNEL_PAT,
    },
    YaraRule {
        id: "yara-jtag-openocd-banner",
        severity: "high",
        description: "OpenOCD/JTAG debug banner string found in firmware image",
        pattern: &[Some(b'O'), Some(b'p'), Some(b'e'), Some(b'n'), Some(b'O'), Some(b'C'), Some(b'D')],
    },
    YaraRule {
        id: "yara-busybox-applet-table",
        severity: "info",
        description: "BusyBox applet table detected — embedded Linux rootfs marker",
        pattern: &[Some(b'B'), Some(b'u'), Some(b's'), Some(b'y'), Some(b'B'), Some(b'o'), Some(b'x')],
    },
    YaraRule {
        id: "yara-dropbear-ssh-banner",
        severity: "medium",
        description: "Dropbear SSH server string detected — verify host key & access controls",
        pattern: &[Some(b'D'), Some(b'r'), Some(b'o'), Some(b'p'), Some(b'b'), Some(b'e'), Some(b'a'), Some(b'r')],
    },
    YaraRule {
        id: "yara-freertos-rtos-marker",
        severity: "info",
        description: "FreeRTOS task/kernel string detected in firmware image",
        pattern: &[Some(b'F'), Some(b'r'), Some(b'e'), Some(b'e'), Some(b'R'), Some(b'T'), Some(b'O'), Some(b'S')],
    },
    YaraRule {
        id: "yara-aes-sbox-constant",
        severity: "info",
        description: "Standard Rijndael AES S-box table prefix detected in firmware image",
        pattern: &[Some(0x63), Some(0x7c), Some(0x77), Some(0x7b), Some(0xf2), Some(0x6b), Some(0x6f), Some(0xc5), Some(0x30), Some(0x01)],
    },
    YaraRule {
        id: "yara-openssh-private-key",
        severity: "critical",
        description: "OpenSSH private key header embedded in firmware",
        pattern: OPENSSH_PAT,
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
        pattern: &[Some(0x00), Some(0x04), Some(b'M'), Some(b'Q'), Some(b'T'), Some(b'T')],
    },
];

fn yara_scan(data: &[u8]) -> Vec<Value> {
    let mut hits = Vec::new();
    for rule in EXTRA_YARA_RULES {
        let pat = rule.pattern;
        if pat.is_empty() || data.len() < pat.len() {
            continue;
        }
        let mut offset = 0_usize;
        let mut count = 0_usize;
        while offset + pat.len() <= data.len() {
            let matched = pat
                .iter()
                .enumerate()
                .all(|(i, byte)| byte.is_none_or(|b| data[offset + i] == b));
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

// ── From-Scratch ELF Header & Defensive Hardening Posture Inspector ──────────

/// Inspect ELF32/ELF64 headers for defensive binary hardening flags (PIE, NX stack, RELRO, Canary).
/// Strictly inspects metadata headers; does not disassemble or decompile instructions.
fn inspect_elf_hardening(data: &[u8]) -> Option<Value> {
    if data.len() < 52 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let class = data[4]; // 1 = 32-bit, 2 = 64-bit
    let endian = data[5]; // 1 = LE, 2 = BE
    let le = endian == 1;
    let r16 = |off: usize| -> u16 {
        let b = [data[off], data[off + 1]];
        if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }
    };
    let r32 = |off: usize| -> u32 {
        let b = [data[off], data[off + 1], data[off + 2], data[off + 3]];
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let r64 = |off: usize| -> u64 {
        let b = [
            data[off], data[off + 1], data[off + 2], data[off + 3],
            data[off + 4], data[off + 5], data[off + 6], data[off + 7],
        ];
        if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }
    };

    let e_type = r16(16);
    let e_machine = r16(18);
    let arch = match e_machine {
        3 => "x86",
        8 => "MIPS",
        40 => "ARM",
        62 => "x86_64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "Unknown/Other",
    };
    let pie_enabled = e_type == 3; // ET_DYN

    let (phoff, phentsize, phnum) = if class == 2 && data.len() >= 64 {
        (r64(32) as usize, r16(54) as usize, r16(56) as usize)
    } else if class == 1 {
        (r32(28) as usize, r16(42) as usize, r16(44) as usize)
    } else {
        return None;
    };

    let mut nx_enabled: Option<bool> = None;
    let mut relro = false;
    if phoff > 0 && phentsize >= 32 {
        for idx in 0..phnum.min(128) {
            let off = phoff + idx * phentsize;
            if off + phentsize > data.len() {
                break;
            }
            let p_type = r32(off);
            let p_flags = if class == 2 { r32(off + 4) } else { r32(off + 24) };
            // PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552, PF_X = 1
            if p_type == 0x6474_e551 {
                nx_enabled = Some((p_flags & 1) == 0);
            } else if p_type == 0x6474_e552 {
                relro = true;
            }
        }
    }

    let stack_canary_symbol = data
        .windows(b"__stack_chk_fail".len())
        .any(|w| w == b"__stack_chk_fail");

    Some(json!({
        "format": if class == 2 { "ELF64" } else { "ELF32" },
        "endianness": if le { "little" } else { "big" },
        "architecture": arch,
        "pie_enabled": pie_enabled,
        "nx_non_executable_stack": nx_enabled,
        "relro_present": relro,
        "stack_canary_symbol_present": stack_canary_symbol
    }))
}

/// Detect plausible ARM Cortex-M bare-metal vector table header at offset 0.
fn inspect_cortex_m_header(data: &[u8]) -> Option<Value> {
    if data.len() < 16 {
        return None;
    }
    let initial_sp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let reset_vec = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    // Cortex-M SRAM lives in 0x2000_0000..0x2FFF_FFFF and Thumb Reset_Handler has LSB=1
    if (0x2000_0000..=0x2fff_ffff).contains(&initial_sp)
        && initial_sp.is_multiple_of(4)
        && (reset_vec & 1) == 1
        && reset_vec > 8
    {
        return Some(json!({
            "architecture_hint": "ARM_Cortex_M_Vector_Table",
            "initial_sp_hex": format!("0x{initial_sp:08x}"),
            "reset_handler_hex": format!("0x{reset_vec:08x}")
        }));
    }
    None
}

// ── Entropy delta analysis ────────────────────────────────────────────────────

fn entropy_delta_analysis(data: &[u8], block_size: usize) -> (f64, usize) {
    let entropies: Vec<f64> = data.chunks(block_size).map(block_entropy).collect();
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
    MagicSig { name: "UBI_Image", bytes: b"UBI#" },
    MagicSig { name: "CramFS_LE", bytes: &[0x45, 0x3d, 0xcd, 0x28] },
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
        let redacted: String = text.chars().take(40).collect();

        // Check each indicator class independently so multiple markers in one banner are all surfaced
        let rules_hit: [(&str, &str, bool); 5] = [
            (
                "critical",
                "embedded-private-key-header",
                lower.contains("-----begin ") && lower.contains("private key"),
            ),
            (
                "high",
                "debug-or-legacy-service-string",
                lower.contains("telnetd") || lower.contains("uart_debug") || lower.contains("jtag_unlock"),
            ),
            (
                "medium",
                "cleartext-http-url",
                lower.contains("http://"),
            ),
            (
                "high",
                "possible-embedded-credential-marker",
                lower.contains("password=") || lower.contains("psk=") || lower.contains("api_key="),
            ),
            (
                "info",
                "firmware-component-banner",
                lower.contains("busybox") || lower.contains("u-boot") || lower.contains("dropbear"),
            ),
        ];

        for (severity, rule, matched) in rules_hit {
            if matched && indicators.len() < 48 {
                indicators.push(json!({
                    "rule_id": rule,
                    "severity": severity,
                    "offset": offset,
                    "offset_hex": format!("0x{offset:08x}"),
                    "excerpt": format!("{redacted}...")
                }));
            }
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

/// Inspect a local hardware firmware binary / flash image (read-only surface review).
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
    let elf_hardening = inspect_elf_hardening(&data);
    let cortex_m_header = inspect_cortex_m_header(&data);

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
    if let Some(ref elf) = elf_hardening {
        if elf["pie_enabled"] == false {
            risk_score = risk_score.saturating_add(12);
        }
        if elf["nx_non_executable_stack"] == false {
            risk_score = risk_score.saturating_add(15);
        }
        if elf["stack_canary_symbol_present"] == false {
            risk_score = risk_score.saturating_add(10);
        }
    }

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
            "Detected {} embedded format signature(s), {} YARA-lite match(es), and {} printable ASCII string(s) ({} security indicator(s)).",
            signatures.len(),
            yara_hits.len(),
            string_count,
            indicators.len()
        ),
    ];

    Ok(json!({
        "schema_version": 3,
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
        "elf_hardening": elf_hardening,
        "cortex_m_header": cortex_m_header,
        "signatures": signatures,
        "indicators": indicators,
        "yara_hits": yara_hits,
        "preview": {
            "entropy_profile": entropy_profile
        },
        "observations": observations,
        "limitations": [
            "Read-only surface metadata triage only; no disassembly, unpacking, or execution is performed.",
            "Binary hardening flags inspect standard ELF program headers for defensive review."
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
        assert_eq!(report["schema_version"], 3);
        assert!(report["metrics"]["signature_count"].as_u64().unwrap() >= 1);
        assert!(report["metrics"]["indicator_count"].as_u64().unwrap() >= 2);
        assert!(report["metrics"]["risk_score"].as_u64().unwrap() >= 30);
        assert!(report["metrics"]["yara_hit_count"].as_u64().unwrap() >= 1);
        assert!(report["metrics"].get("max_entropy_drop_bits").is_some());
    }

    #[test]
    fn inspects_elf64_hardening_posture() {
        let mut elf = vec![0u8; 128];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELF64
        elf[5] = 1; // LE
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC (no PIE)
        elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // AArch64
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        // Program header at offset 64: PT_GNU_STACK (0x6474e551) with PF_R|PF_W|PF_X (7)
        elf[64..68].copy_from_slice(&0x6474_e551u32.to_le_bytes());
        elf[68..72].copy_from_slice(&7u32.to_le_bytes());

        let hard = inspect_elf_hardening(&elf).unwrap();
        assert_eq!(hard["architecture"], "AArch64");
        assert_eq!(hard["pie_enabled"], false);
        assert_eq!(hard["nx_non_executable_stack"], false);
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
