from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 2 * 1024 * 1024
EXCLUDED_DIRECTORIES = {
    ".git",
    ".venv",
    ".venv-1",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
}
SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".ts",
    ".tsx",
}
RULES = (
    (
        "dynamic-evaluation",
        "high",
        re.compile(r"\b(?:eval|exec)\s*\("),
        "Review dynamic code evaluation; prefer explicit parsing or fixed dispatch.",
    ),
    (
        "shell-command",
        "high",
        re.compile(
            r"\b(?:subprocess\.(?:run|Popen|call|check_call|check_output)|os\.system)"
            r"\s*\(.*(?:shell\s*=\s*True|os\.system)"
        ),
        "Avoid shell interpretation of untrusted input; use argument arrays and validation.",
    ),
    (
        "disabled-tls-verification",
        "medium",
        re.compile(r"\bverify\s*=\s*False\b"),
        "Keep TLS certificate verification enabled outside isolated tests.",
    ),
    (
        "possible-hardcoded-secret",
        "high",
        re.compile(
            r"""(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*"""
            r"""(['"])(?!\s*(?:your[-_ ]|example|placeholder|changeme|xxx))[^'"]{8,}\1"""
        ),
        "Move credentials to a secret store or environment variable; do not commit values.",
    ),
)


def scan_source_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Source root is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    scanned_files = 0
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in EXCLUDED_DIRECTORIES
        )
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path.suffix.lower() not in SOURCE_SUFFIXES or path.is_symlink():
                continue
            if scanned_files >= MAX_SOURCE_FILES:
                raise ValueError(f"Source tree exceeds the {MAX_SOURCE_FILES:,} file scan limit.")
            if path.stat().st_size > MAX_SOURCE_BYTES:
                warnings.append(
                    f"Skipped oversized source file: {path.relative_to(root).as_posix()}"
                )
                continue
            try:
                lines = path.read_text(encoding="utf-8-sig").splitlines()
            except UnicodeDecodeError:
                warnings.append(
                    f"Skipped non-UTF-8 source file: {path.relative_to(root).as_posix()}"
                )
                continue

            scanned_files += 1
            relative = path.relative_to(root).as_posix()
            for line_number, line in enumerate(lines, start=1):
                for rule_id, severity, pattern, recommendation in RULES:
                    if pattern.search(line):
                        findings.append(
                            {
                                "rule_id": rule_id,
                                "severity": severity,
                                "path": relative,
                                "line": line_number,
                                "recommendation": recommendation,
                            }
                        )

    return {
        "schema_version": 1,
        "analysis": "local_static_source_review",
        "root_name": root.name,
        "metrics": {
            "scanned_files": scanned_files,
            "finding_count": len(findings),
            "warning_count": len(warnings),
        },
        "findings": findings,
        "warnings": warnings,
        "limitations": [
            "This local, read-only pattern scan is not a complete security audit.",
            "Findings require manual review and may be false positives or missed issues.",
            "The scanner does not execute code, contact targets, or test exploitability.",
        ],
    }
