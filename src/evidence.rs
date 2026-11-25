use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const EXCLUDED_DIRECTORIES: &[&str] = &[".git", ".cache", "target"];

#[derive(Clone, Debug, Deserialize)]
struct ManifestEntry {
    path: String,
    size_bytes: u64,
    sha256: String,
}

fn is_excluded(entry: &DirEntry) -> bool {
    entry.depth() > 0
        && entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| EXCLUDED_DIRECTORIES.contains(&name))
}

fn relative_name(root: &Path, path: &Path) -> Result<String> {
    let relative = path.strip_prefix(root)?;
    Ok(relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/"))
}

fn hash_stable_file(path: &Path) -> Result<(u64, String)> {
    let before = fs::metadata(path)?;
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = fs::metadata(path)?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        bail!("Evidence file changed while hashing: {}", path.display());
    }
    Ok((after.len(), format!("{:x}", digest.finalize())))
}

fn collect_entries(root: &Path) -> Result<Vec<Value>> {
    let mut entries = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded(entry))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let (size, digest) = hash_stable_file(entry.path())
            .with_context(|| format!("Hashing evidence file {}", entry.path().display()))?;
        entries.push(json!({
            "path": relative_name(root, entry.path())?,
            "size_bytes": size,
            "sha256": digest
        }));
    }
    entries.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
    Ok(entries)
}

pub fn create_manifest(root: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Resolving evidence directory {}", root.display()))?;
    if !root.is_dir() {
        bail!("Evidence root is not a directory: {}", root.display());
    }
    let entries = collect_entries(&root)?;
    Ok(json!({
        "schema_version": 1,
        "analysis": "local_evidence_inventory",
        "root_name": root.file_name().unwrap_or_default().to_string_lossy(),
        "entry_count": entries.len(),
        "entries": entries,
        "limitations": [
            "This inventory records file paths, sizes, and SHA-256 hashes only.",
            "It does not establish acquisition history, authenticity, or legal chain of custody.",
            "Version-control, virtual-environment, build, and cache directories are excluded."
        ]
    }))
}

fn safe_manifest_path(name: &str) -> Result<PathBuf> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || name.contains('\0')
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("Evidence manifest contains a path outside the evidence root.");
    }
    Ok(path.to_path_buf())
}

pub fn verify_manifest(root: &Path, manifest_path: &Path) -> Result<Value> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Resolving evidence directory {}", root.display()))?;
    if !root.is_dir() {
        bail!("Evidence root is not a directory: {}", root.display());
    }
    let manifest_path = manifest_path
        .canonicalize()
        .with_context(|| format!("Resolving manifest {}", manifest_path.display()))?;
    if manifest_path.starts_with(&root) {
        bail!("Keep the evidence manifest outside the evidence directory.");
    }
    if fs::metadata(&manifest_path)?.len() > 64 * 1024 * 1024 {
        bail!("Manifest exceeds the 64 MiB size limit.");
    }
    let manifest: Value = serde_json::from_slice(&fs::read(&manifest_path)?)
        .context("Could not read a valid evidence manifest.")?;
    let entries: Vec<ManifestEntry> = serde_json::from_value(
        manifest
            .get("entries")
            .cloned()
            .context("Evidence manifest must contain an entries list.")?,
    )
    .context("Evidence manifest contains an invalid entry.")?;

    let mut expected = BTreeMap::new();
    for entry in entries {
        if entry.sha256.len() != 64
            || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || expected.contains_key(&entry.path)
        {
            bail!("Evidence manifest contains an invalid or duplicate hash entry.");
        }
        safe_manifest_path(&entry.path)?;
        expected.insert(entry.path.clone(), entry);
    }
    let current_entries = collect_entries(&root)?;
    let mut current = BTreeMap::new();
    for entry in current_entries {
        let parsed: ManifestEntry = serde_json::from_value(entry)?;
        current.insert(parsed.path.clone(), parsed);
    }

    let expected_paths: BTreeSet<_> = expected.keys().cloned().collect();
    let current_paths: BTreeSet<_> = current.keys().cloned().collect();
    let missing: Vec<_> = expected_paths.difference(&current_paths).cloned().collect();
    let added: Vec<_> = current_paths.difference(&expected_paths).cloned().collect();
    let changed: Vec<_> = expected_paths
        .intersection(&current_paths)
        .filter(|path| {
            let old = &expected[*path];
            let new = &current[*path];
            old.sha256 != new.sha256 || old.size_bytes != new.size_bytes
        })
        .cloned()
        .collect();
    let unchanged_count = expected_paths.intersection(&current_paths).count() - changed.len();
    Ok(json!({
        "schema_version": 1,
        "analysis": "local_evidence_verification",
        "root_name": root.file_name().unwrap_or_default().to_string_lossy(),
        "verified": missing.is_empty() && added.is_empty() && changed.is_empty(),
        "summary": {
            "unchanged_count": unchanged_count,
            "missing_count": missing.len(),
            "added_count": added.len(),
            "changed_count": changed.len()
        },
        "missing": missing,
        "added": added,
        "changed": changed,
        "limitations": [
            "Verification compares current file bytes with the supplied manifest.",
            "It does not prove that the original manifest or evidence was authentic."
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "iq-workbench-evidence-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn manifest_verification_detects_changed_files() {
        let root = temp_dir();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("note.txt"), "original").unwrap();
        let manifest = create_manifest(&root).unwrap();
        let manifest_path = root.with_extension("json");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        assert_eq!(
            verify_manifest(&root, &manifest_path).unwrap()["verified"],
            true
        );
        fs::write(root.join("note.txt"), "changed").unwrap();
        let result = verify_manifest(&root, &manifest_path).unwrap();
        assert_eq!(result["changed"][0], "note.txt");

        fs::remove_file(manifest_path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_parent_paths_in_manifest() {
        let root = temp_dir();
        fs::create_dir_all(&root).unwrap();
        let manifest_path = root.with_extension("json");
        fs::write(
            &manifest_path,
            r#"{"entries":[{"path":"../outside","size_bytes":1,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}"#,
        )
        .unwrap();
        assert!(verify_manifest(&root, &manifest_path).is_err());
        fs::remove_file(manifest_path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
