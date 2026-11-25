from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

EXCLUDED_DIRECTORIES = {".git", ".venv", ".venv-1", "__pycache__", ".pytest_cache"}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def create_manifest(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Evidence root is not a directory: {root}")

    entries = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRECTORIES for part in relative.parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        before = path.stat()
        digest = _sha256_file(path)
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError(f"Evidence file changed while hashing: {path}")
        entries.append(
            {
                "path": relative.as_posix(),
                "size_bytes": after.st_size,
                "sha256": digest,
            }
        )

    return {
        "schema_version": 1,
        "analysis": "local_evidence_inventory",
        "root_name": root.name,
        "entry_count": len(entries),
        "entries": entries,
        "limitations": [
            "This inventory records file paths, sizes, and SHA-256 hashes only.",
            "It does not establish acquisition history, authenticity, or legal chain of custody.",
            "Version-control, virtual-environment, and Python cache directories are excluded.",
        ],
    }


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read a valid evidence manifest: {manifest_path}") from error
    if not isinstance(manifest, dict) or not isinstance(manifest.get("entries"), list):
        raise ValueError("Evidence manifest must contain an entries list.")

    expected: dict[str, dict[str, Any]] = {}
    for entry in manifest["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("Evidence manifest contains an invalid entry.")
        relative = entry.get("path")
        digest = entry.get("sha256")
        size = entry.get("size_bytes")
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest.lower())
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or "\0" in relative
        ):
            raise ValueError("Evidence manifest contains an invalid path, hash, or size.")
        parsed = PurePosixPath(relative)
        windows_path = PureWindowsPath(relative)
        if (
            parsed.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or ".." in parsed.parts
            or ".." in windows_path.parts
            or not parsed.parts
        ):
            raise ValueError("Evidence manifest contains a path outside the evidence root.")
        if relative in expected:
            raise ValueError("Evidence manifest contains duplicate paths.")
        expected[relative] = entry

    current_manifest = create_manifest(root)
    current = {entry["path"]: entry for entry in current_manifest["entries"]}
    missing = sorted(set(expected) - set(current))
    added = sorted(set(current) - set(expected))
    changed = sorted(
        path
        for path in set(expected) & set(current)
        if expected[path]["sha256"] != current[path]["sha256"]
        or expected[path]["size_bytes"] != current[path]["size_bytes"]
    )
    return {
        "schema_version": 1,
        "analysis": "local_evidence_verification",
        "root_name": Path(root).resolve().name,
        "verified": not missing and not added and not changed,
        "summary": {
            "unchanged_count": len(set(expected) & set(current)) - len(changed),
            "missing_count": len(missing),
            "added_count": len(added),
            "changed_count": len(changed),
        },
        "missing": missing,
        "added": added,
        "changed": changed,
        "limitations": [
            "Verification compares current file bytes with the supplied manifest.",
            "It does not prove that the original manifest or evidence was authentic.",
        ],
    }
