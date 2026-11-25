use anyhow::{Context, Result, bail};
use regex::Regex;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use walkdir::{DirEntry, WalkDir};

const MAX_SOURCE_FILES: usize = 20_000;
const MAX_SOURCE_BYTES: u64 = 2 * 1024 * 1024;
const EXCLUDED_DIRECTORIES: &[&str] = &[".git", ".cache", "node_modules", "target"];
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "cs", "go", "h", "hpp", "java", "js", "jsx", "php", "rb", "rs", "ts", "tsx",
];

struct Rule {
    id: &'static str,
    severity: &'static str,
    pattern: Regex,
    recommendation: &'static str,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            Rule {
                id: "process-launch",
                severity: "medium",
                pattern: Regex::new(r"\b(?:Command::new|std::process::Command)\b").unwrap(),
                recommendation: "Review command construction and ensure untrusted input is not interpreted by a shell.",
            },
            Rule {
                id: "unsafe-rust",
                severity: "medium",
                pattern: Regex::new(r"\bunsafe\s*\{").unwrap(),
                recommendation: "Review unsafe blocks for pointer, aliasing, and lifetime invariants.",
            },
            Rule {
                id: "disabled-tls-verification",
                severity: "high",
                pattern: Regex::new(r"\bdanger_accept_invalid_certs\s*\(\s*true\s*\)").unwrap(),
                recommendation: "Keep TLS certificate verification enabled outside isolated tests.",
            },
            Rule {
                id: "possible-hardcoded-secret",
                severity: "high",
                pattern: Regex::new(
                    r#"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*["'][^"']{8,}["']"#,
                )
                .unwrap(),
                recommendation: "Move credentials to a secret store or environment variable; do not commit values.",
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
                    findings.push(json!({
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "path": relative,
                        "line": line_number + 1,
                        "recommendation": rule.recommendation
                    }));
                }
            }
        }
    }

    Ok(json!({
        "schema_version": 1,
        "analysis": "local_static_source_review",
        "root_name": root.file_name().unwrap_or_default().to_string_lossy(),
        "metrics": {
            "scanned_files": scanned_files,
            "finding_count": findings.len(),
            "warning_count": warnings.len()
        },
        "findings": findings,
        "warnings": warnings,
        "limitations": [
            "This local, read-only pattern scan is not a complete security audit.",
            "Findings require manual review and may be false positives or missed issues.",
            "The scanner does not execute code, contact targets, or test exploitability."
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn reports_rust_unsafe_pattern_without_source_text() {
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
        let report = scan_source_tree(&root).unwrap();
        fs::remove_dir_all(root).unwrap();
        assert_eq!(report["findings"][0]["rule_id"], "unsafe-rust");
        assert!(report["findings"][0].get("source").is_none());
    }
}
