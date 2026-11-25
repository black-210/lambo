use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::{DirEntry, WalkDir};

const MAX_SOURCE_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const EXCLUDED_DIRECTORIES: &[&str] = &[".git", ".cache", "node_modules", "target"];
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cs", "go", "h", "hpp", "java", "js", "jsx", "php", "py", "rb", "rs", "ts",
    "tsx", "v", "sv", "vhd", "vhdl", "dts", "dtsi", "conf", "cfg", "ini", "toml", "yaml", "yml",
    "env", "sh", "cmake", "mk",
];

struct Rule {
    id: &'static str,
    category: &'static str,
    cwe: &'static str,
    severity: &'static str,
    weight: u32,
    pattern: Regex,
    recommendation: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            Rule {
                id: "hw-jtag-swd-unlocked",
                category: "hardware_interface",
                cwe: "CWE-284",
                severity: "high",
                weight: 18,
                pattern: Regex::new(
                    r"(?i)\b(?:ENABLE_JTAG|JTAG_UNLOCK|SWD_DEBUG_ENABLE|RDP_LEVEL_0|DBGMCU_CR|DEBUG_PORT_UNLOCK)\b",
                )
                .unwrap(),
                recommendation: "Disable JTAG/SWD debug access and enable flash readout protection (RDP) in production hardware builds.",
            },
            Rule {
                id: "hw-uart-debug-console",
                category: "hardware_interface",
                cwe: "CWE-284",
                severity: "medium",
                weight: 10,
                pattern: Regex::new(
                    r"(?i)\b(?:ENABLE_UART_SHELL|UART_DEBUG_CONSOLE|CONFIG_SERIAL_CONSOLE|ROOT_SHELL_UART)\b|console=tty(?:S|AMA|USB)",
                )
                .unwrap(),
                recommendation: "Restrict or disable interactive UART/serial debug consoles on production PCB revisions.",
            },
            Rule {
                id: "hw-secure-boot-bypass",
                category: "hardware_interface",
                cwe: "CWE-345",
                severity: "critical",
                weight: 25,
                pattern: Regex::new(
                    r"(?i)\b(?:SECURE_BOOT\s*=\s*0|SECURE_BOOT_DISABLED|ALLOW_UNSIGNED_FIRMWARE|SKIP_SIG_VERIFY)\b",
                )
                .unwrap(),
                recommendation: "Enforce cryptographic firmware signature verification and hardware secure-boot fuses before deployment.",
            },
            Rule {
                id: "hw-watchdog-or-bor-disabled",
                category: "hardware_interface",
                cwe: "CWE-693",
                severity: "medium",
                weight: 12,
                pattern: Regex::new(
                    r"(?i)\b(?:WDT_DISABLE|DISABLE_WATCHDOG|BOR_OFF|BROWNOUT_DISABLED)\b",
                )
                .unwrap(),
                recommendation: "Keep hardware watchdog timers and brown-out reset (BOR) detectors enabled to resist fault/voltage-glitch anomalies.",
            },
            Rule {
                id: "hw-telnet-or-empty-root",
                category: "hardware_interface",
                cwe: "CWE-284",
                severity: "critical",
                weight: 25,
                pattern: Regex::new(
                    r"\b(?:telnetd|PermitEmptyPasswords\s+yes|NOPASSWD:\s*ALL)\b|root::0:0:",
                )
                .unwrap(),
                recommendation: "Remove legacy Telnet daemons, passwordless sudo, and empty root entries from embedded rootfs images.",
            },
            Rule {
                id: "unsafe-c-buffer-api",
                category: "memory_safety",
                cwe: "CWE-119",
                severity: "high",
                weight: 15,
                pattern: Regex::new(r"\b(?:gets|strcpy|strcat|sprintf|vsprintf)\s*\(").unwrap(),
                recommendation: "Replace unbounded C string/buffer functions with bounds-checked alternatives (snprintf, strlcpy, or safe slices).",
            },
            Rule {
                id: "unsafe-memcpy-review",
                category: "memory_safety",
                cwe: "CWE-120",
                severity: "medium",
                weight: 8,
                pattern: Regex::new(r"\b(?:memcpy|memmove)\s*\([^,]+,[^,]+,\s*[a-zA-Z_]").unwrap(),
                recommendation: "Verify dynamic copy lengths against destination buffer capacity before memcpy/memmove in firmware drivers.",
            },
            Rule {
                id: "weak-prng",
                category: "crypto_weakness",
                cwe: "CWE-330",
                severity: "medium",
                weight: 10,
                pattern: Regex::new(r"\b(?:rand|srand)\s*\(").unwrap(),
                recommendation: "Use a hardware TRNG or cryptographically secure PRNG for security-sensitive tokens, keys, or nonces.",
            },
            Rule {
                id: "legacy-weak-crypto",
                category: "crypto_weakness",
                cwe: "CWE-327",
                severity: "medium",
                weight: 12,
                pattern: Regex::new(
                    r"\b(?:MD5_Init|SHA1_Init|DES_ecb_encrypt|RC4_set_key|hashlib\.md5|hashlib\.sha1)\b",
                )
                .unwrap(),
                recommendation: "Migrate away from legacy MD5/SHA-1/DES/RC4 primitives to modern authenticated algorithms (SHA-256, AES-GCM, ChaCha20-Poly1305).",
            },
            Rule {
                id: "process-launch",
                category: "privilege_exec",
                cwe: "CWE-78",
                severity: "medium",
                weight: 8,
                pattern: Regex::new(
                    r"\b(?:Command::new|std::process::Command)\b|\b(?:system|popen)\s*\(",
                )
                .unwrap(),
                recommendation: "Review command construction and ensure untrusted input is never interpreted by a shell.",
            },
            Rule {
                id: "weak-file-permissions",
                category: "privilege_exec",
                cwe: "CWE-732",
                severity: "medium",
                weight: 10,
                pattern: Regex::new(r"\bchmod\s+(?:0?777|a\+rwx)\b").unwrap(),
                recommendation: "Apply least-privilege permissions to device nodes, configs, and firmware artifacts instead of 0777.",
            },
            Rule {
                id: "unsafe-rust",
                category: "memory_safety",
                cwe: "CWE-119",
                severity: "medium",
                weight: 8,
                pattern: Regex::new(r"\bunsafe\s*\{").unwrap(),
                recommendation: "Audit unsafe blocks for MMIO pointer validity, aliasing, alignment, and lifetime invariants.",
            },
            Rule {
                id: "disabled-tls-verification",
                category: "transport_security",
                cwe: "CWE-295",
                severity: "high",
                weight: 18,
                pattern: Regex::new(
                    r"\bdanger_accept_invalid_certs\s*\(\s*true\s*\)|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|\bSSL_VERIFY_NONE\b",
                )
                .unwrap(),
                recommendation: "Keep TLS certificate verification enabled outside isolated test harnesses.",
            },
            Rule {
                id: "embedded-private-key-pem",
                category: "secrets",
                cwe: "CWE-798",
                severity: "critical",
                weight: 25,
                pattern: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(),
                recommendation: "Remove private key material from source/firmware trees and store keys in a hardware secure element.",
            },
            Rule {
                id: "possible-hardcoded-secret",
                category: "secrets",
                cwe: "CWE-798",
                severity: "critical",
                weight: 22,
                pattern: Regex::new(
                    r#"(?i)\b(?:api[_-]?key|secret|password|token|psk|private[_-]?key|aes[_-]?key|wifi_pass|ble_pin|wpa_psk)\b\s*[:=]\s*["'][^"']{4,}["']"#,
                )
                .unwrap(),
                recommendation: "Provision secrets via hardware keystore/secure element or environment; never hardcode credentials in firmware/source.",
            },
            // ── NEW RULES ──────────────────────────────────────────────────────
            Rule {
                id: "unsafe-format-string",
                category: "memory_safety",
                cwe: "CWE-134",
                severity: "high",
                weight: 18,
                pattern: Regex::new(r"\b(?:printf|fprintf|sprintf|syslog)\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*[,)]")
                    .unwrap(),
                recommendation: "Pass format strings as literals or validate them; user-controlled format strings enable arbitrary memory read/write.",
            },
            Rule {
                id: "stack-canary-disabled",
                category: "memory_safety",
                cwe: "CWE-693",
                severity: "high",
                weight: 16,
                pattern: Regex::new(
                    r"(?i)\b(?:-fno-stack-protector|STACK_PROTECTOR\s*=\s*0|CONFIG_CC_STACKPROTECTOR\s*=\s*n|__attribute__\s*\(\s*\(\s*no_stack_protector\s*\)\s*\))\b",
                )
                .unwrap(),
                recommendation: "Enable -fstack-protector-strong for all firmware translation units to detect stack smashing at runtime.",
            },
            Rule {
                id: "hardcoded-ssh-host-key",
                category: "secrets",
                cwe: "CWE-321",
                severity: "critical",
                weight: 25,
                pattern: Regex::new(r"(?i)\b(?:dropbear_rsa_host_key|dropbear_dss_host_key|ssh_host_rsa_key|ssh_host_ecdsa_key|ssh_host_ed25519_key)\b")
                    .unwrap(),
                recommendation: "Generate SSH host keys at first boot instead of bundling fixed keys; identical keys across units break device identity.",
            },
            Rule {
                id: "hw-ble-just-works-pairing",
                category: "wireless_security",
                cwe: "CWE-287",
                severity: "high",
                weight: 16,
                pattern: Regex::new(r"(?i)\b(?:IO_CAPABILITY_NO_INPUT_NO_OUTPUT|BLE_GAP_IO_CAPS_NONE|SMP_IO_NO_INPUT_NO_OUTPUT|ALLOW_UNAUTH_BLE_BONDING)\b")
                    .unwrap(),
                recommendation: "Enforce Numeric Comparison or Passkey Entry (LE Secure Connections MITM protection) instead of Just-Works BLE pairing.",
            },
            Rule {
                id: "crypto-ecb-or-static-iv",
                category: "crypto_weakness",
                cwe: "CWE-327",
                severity: "high",
                weight: 16,
                pattern: Regex::new(r"(?i)\b(?:AES_ECB|CIPHER_MODE_ECB|mbedtls_aes_crypt_ecb|STATIC_AES_IV)\b")
                    .unwrap(),
                recommendation: "Replace deterministic ECB mode or static IVs with authenticated encryption (AES-GCM or ChaCha20-Poly1305) and unique hardware TRNG nonces.",
            },
            Rule {
                id: "hw-unauthenticated-ota",
                category: "hardware_interface",
                cwe: "CWE-494",
                severity: "critical",
                weight: 22,
                pattern: Regex::new(r"(?i)\b(?:OTA_SKIP_VERIFY|ALLOW_HTTP_OTA|VERIFY_FW_SIG\s*=\s*0|OTA_NO_ROLLBACK_CHECK)\b")
                    .unwrap(),
                recommendation: "Verify signed firmware digests and anti-rollback counters prior to staging any OTA image.",
            },
        ]
    })
}

fn is_excluded(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| EXCLUDED_DIRECTORIES.contains(&name))
}

pub fn scan_source_tree(root: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Resolving source directory {}", root.display()))?;
    if !root.is_dir() {
        bail!("Source root is not a directory: {}", root.display());
    }

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    let mut scanned_files = 0;
    let mut by_severity: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_category: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut raw_score: u32 = 0;

    for entry in WalkDir::new(&root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded(entry))
    {
        let entry = entry?;
        if !entry.file_type().is_file() || entry.path_is_symlink() {
            continue;
        }
        let extension = entry.path().extension().and_then(|value| value.to_str());
        if !extension
            .is_some_and(|value| SOURCE_EXTENSIONS.contains(&value.to_ascii_lowercase().as_str()))
        {
            continue;
        }
        if scanned_files >= MAX_SOURCE_FILES {
            bail!("Source tree exceeds the {MAX_SOURCE_FILES} file scan limit.");
        }
        if entry.metadata()?.len() > MAX_SOURCE_BYTES {
            warnings.push(format!(
                "Skipped oversized source file: {}",
                entry.path().strip_prefix(&root)?.to_string_lossy()
            ));
            continue;
        }
        let content = match fs::read_to_string(entry.path()) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                warnings.push(format!(
                    "Skipped non-UTF-8 source file: {}",
                    entry.path().strip_prefix(&root)?.to_string_lossy()
                ));
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("Reading {}", entry.path().display()));
            }
        };
        scanned_files += 1;
        let relative = entry
            .path()
            .strip_prefix(&root)?
            .to_string_lossy()
            .replace('\\', "/");
        for (line_number, line) in content.lines().enumerate() {
            for rule in rules() {
                if rule.pattern.is_match(line) {
                    if rule.id == "possible-hardcoded-secret"
                        && ["your-", "example", "placeholder", "changeme", "xxx"]
                            .iter()
                            .any(|marker| line.to_ascii_lowercase().contains(marker))
                    {
                        continue;
                    }
                    *by_severity.entry(rule.severity).or_insert(0) += 1;
                    *by_category.entry(rule.category).or_insert(0) += 1;
                    raw_score = raw_score.saturating_add(rule.weight);
                    findings.push(json!({
                        "rule_id": rule.id,
                        "category": rule.category,
                        "cwe": rule.cwe,
                        "severity": rule.severity,
                        "path": relative,
                        "line": line_number + 1,
                        "recommendation": rule.recommendation
                    }));
                }
            }
        }
    }

    let risk_score = raw_score.min(100);
    Ok(json!({
        "schema_version": 2,
        "analysis": "local_hardware_firmware_static_review",
        "root_name": root.file_name().unwrap_or_default().to_string_lossy(),
        "metrics": {
            "scanned_files": scanned_files,
            "finding_count": findings.len(),
            "warning_count": warnings.len(),
            "risk_score": risk_score,
            "by_severity": by_severity,
            "by_category": by_category
        },
        "findings": findings,
        "warnings": warnings,
        "limitations": [
            "This local, read-only pattern scan is not a complete firmware or hardware audit.",
            "Findings require manual expert review and may contain false positives.",
            "The scanner does not execute code, flash devices, contact targets, or test exploitability."
        ]
    }))
}

pub fn audit_to_sarif(audit_report: &Value) -> Result<Value> {
    let findings = audit_report["findings"]
        .as_array()
        .context("Audit report does not contain a findings array.")?;

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let sev = match f["severity"].as_str().unwrap_or("medium") {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "note",
            };
            json!({
                "ruleId": f["rule_id"],
                "level": sev,
                "message": {
                    "text": format!(
                        "[{} / {}] {}",
                        f["category"].as_str().unwrap_or("hardware"),
                        f["cwe"].as_str().unwrap_or("CWE"),
                        f["recommendation"].as_str().unwrap_or("")
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f["path"] },
                        "region": { "startLine": f["line"].as_u64().unwrap_or(1) }
                    }
                }]
            })
        })
        .collect();

    Ok(json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "iq-research-workbench",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://local.offline/iq-workbench"
                }
            },
            "results": results
        }]
    }))
}

pub fn scan_for_issues(root_path: &str) -> Result<Value> {
    scan_source_tree(Path::new(root_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn reports_rust_unsafe_and_hardware_flags_without_source_text() {
        let root = std::env::temp_dir().join(format!(
            "iq-workbench-audit-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sample.rs"), "unsafe { do_work(); }\n").unwrap();
        fs::write(root.join("board.cfg"), "ENABLE_JTAG=1\nSECURE_BOOT=0\nWDT_DISABLE=1\n").unwrap();
        let report = scan_source_tree(&root).unwrap();
        let sarif = audit_to_sarif(&report).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(report["metrics"]["finding_count"], 4);
        assert!(report["findings"][0].get("source").is_none());
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 4);
    }
}
