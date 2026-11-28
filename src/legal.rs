use crate::common::sha256_bytes;
use anyhow::{Context, Result, bail};
use hex::encode_to_slice;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationScope {
    pub schema_version: u32,
    pub engagement_id: String,
    pub operator: String,
    pub authorizing_entity: String,
    pub authorization_ref: String,
    pub target_description: String,
    pub offline_only: bool,
    pub valid_from: String,
    pub valid_until: String,
    pub notes: String,
}

impl AuthorizationScope {
    pub fn template(engagement_id: &str, operator: &str) -> Self {
        Self {
            schema_version: 1,
            engagement_id: engagement_id.to_owned(),
            operator: operator.to_owned(),
            authorizing_entity: "Authorized Hardware Lab / Asset Owner".to_owned(),
            authorization_ref: "AUTH-LAB-2026-001".to_owned(),
            target_description: "Offline captured IQ traces, power/EM lab traces, and local firmware source".to_owned(),
            offline_only: true,
            valid_from: "2026-01-01".to_owned(),
            valid_until: "2027-12-31".to_owned(),
            notes: "Strictly authorized offline defensive and red-team assessment. No active RF emission or unauthorized device access.".to_owned(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.engagement_id.trim().is_empty() {
            bail!("Authorization scope requires a non-empty engagement_id.");
        }
        if self.operator.trim().is_empty() {
            bail!("Authorization scope requires a non-empty operator.");
        }
        if self.authorizing_entity.trim().is_empty() {
            bail!("Authorization scope requires an authorizing_entity.");
        }
        if self.authorization_ref.trim().is_empty() {
            bail!("Authorization scope requires an authorization_ref.");
        }
        if self.target_description.trim().is_empty() {
            bail!("Authorization scope requires a target_description.");
        }
        if !self.offline_only {
            bail!("This workbench permits strictly offline_only=true authorized assessments.");
        }
        Ok(())
    }
}

pub fn create_scope_file(path: &Path, engagement_id: &str, operator: &str) -> Result<Value> {
    let scope = AuthorizationScope::template(engagement_id, operator);
    scope.validate()?;
    let bytes = serde_json::to_vec_pretty(&scope)?;
    fs::write(path, [&bytes[..], b"\n"].concat())
        .with_context(|| format!("Writing scope file {}", path.display()))?;
    Ok(json!({
        "schema_version": 1,
        "analysis": "legal_authorization_scope_created",
        "path": path.to_string_lossy(),
        "scope_sha256": sha256_bytes(&bytes),
        "scope": scope
    }))
}

pub fn verify_scope_file(path: &Path) -> Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("Reading scope file {}", path.display()))?;
    let scope: AuthorizationScope =
        serde_json::from_slice(&bytes).context("Parsing authorization scope JSON.")?;
    scope.validate()?;
    Ok(json!({
        "schema_version": 1,
        "analysis": "legal_authorization_scope_verified",
        "valid": true,
        "scope_sha256": sha256_bytes(&bytes),
        "engagement_id": scope.engagement_id,
        "operator": scope.operator,
        "authorizing_entity": scope.authorizing_entity,
        "authorization_ref": scope.authorization_ref,
        "offline_only": scope.offline_only,
        "valid_from": scope.valid_from,
        "valid_until": scope.valid_until
    }))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditLedgerEntry {
    pub seq: u64,
    pub timestamp_unix: u64,
    pub action: String,
    pub scope_sha256: Option<String>,
    pub report_sha256: String,
    pub summary: String,
    pub prev_hash: String,
    pub entry_hash: String,
}

fn compute_entry_hash(
    seq: u64,
    timestamp_unix: u64,
    action: &str,
    scope_sha256: Option<&str>,
    report_sha256: &str,
    summary: &str,
    prev_hash: &str,
) -> String {
    let canonical = json!({
        "seq": seq,
        "timestamp_unix": timestamp_unix,
        "action": action,
        "scope_sha256": scope_sha256,
        "report_sha256": report_sha256,
        "summary": summary,
        "prev_hash": prev_hash
    });
    sha256_bytes(canonical.to_string().as_bytes())
}

pub fn append_audit_entry(
    ledger_path: &Path,
    action: &str,
    scope_sha256: Option<&str>,
    report_sha256: &str,
    summary: &str,
) -> Result<AuditLedgerEntry> {
    let mut seq = 1_u64;
    let mut prev_hash = "0".repeat(64);
    if ledger_path.exists() {
        let file = fs::File::open(ledger_path)
            .with_context(|| format!("Reading audit ledger {}", ledger_path.display()))?;
        for line in BufReader::new(file).lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditLedgerEntry =
                serde_json::from_str(&line).context("Invalid audit ledger entry.")?;
            seq = entry.seq + 1;
            prev_hash = entry.entry_hash;
        }
    }
    let timestamp_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let entry_hash = compute_entry_hash(
        seq,
        timestamp_unix,
        action,
        scope_sha256,
        report_sha256,
        summary,
        &prev_hash,
    );
    let entry = AuditLedgerEntry {
        seq,
        timestamp_unix,
        action: action.to_owned(),
        scope_sha256: scope_sha256.map(str::to_owned),
        report_sha256: report_sha256.to_owned(),
        summary: summary.to_owned(),
        prev_hash,
        entry_hash,
    };
    if let Some(parent) = ledger_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .with_context(|| format!("Opening audit ledger {}", ledger_path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&entry)?)?;
    Ok(entry)
}

pub fn verify_audit_ledger(ledger_path: &Path) -> Result<Value> {
    let file = fs::File::open(ledger_path)
        .with_context(|| format!("Opening audit ledger {}", ledger_path.display()))?;
    let mut expected_prev = "0".repeat(64);
    let mut expected_seq = 1_u64;
    let mut count = 0_u64;
    let mut broken_at = Vec::new();

    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditLedgerEntry = serde_json::from_str(&line)
            .with_context(|| format!("Malformed ledger JSON on line {}", idx + 1))?;
        let recomputed = compute_entry_hash(
            entry.seq,
            entry.timestamp_unix,
            &entry.action,
            entry.scope_sha256.as_deref(),
            &entry.report_sha256,
            &entry.summary,
            &entry.prev_hash,
        );
        if entry.seq != expected_seq
            || entry.prev_hash != expected_prev
            || entry.entry_hash != recomputed
        {
            broken_at.push(idx + 1);
        }
        expected_prev = entry.entry_hash;
        expected_seq = entry.seq + 1;
        count += 1;
    
    }
    Ok(json!({
        "schema_version": 1,
        "analysis": "tamper_evident_audit_ledger_verification",
        "valid": broken_at.is_empty() && count > 0,
        "entry_count": count,
        "broken_lines": broken_at,
        "head_hash": if count > 0 { json!(expected_prev) } else { Value::Null }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn scope_and_ledger_hash_chain_verify() {
        let dir = std::env::temp_dir().join(format!(
            "iq-legal-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let scope_path = dir.join("scope.json");
        let ledger_path = dir.join("ledger.jsonl");

        let created = create_scope_file(&scope_path, "ENG-01", "analyst").unwrap();
        let scope_hash = created["scope_sha256"].as_str().unwrap();
        assert_eq!(verify_scope_file(&scope_path).unwrap()["valid"], true);

        append_audit_entry(&ledger_path, "assess", Some(scope_hash), "abcd", "Run 1").unwrap();
        append_audit_entry(&ledger_path, "audit", Some(scope_hash), "ef01", "Run 2").unwrap();
        let verified = verify_audit_ledger(&ledger_path).unwrap();
        assert_eq!(verified["valid"], true);
        assert_eq!(verified["entry_count"], 2);

        fs::remove_dir_all(dir).unwrap();
    }
}
