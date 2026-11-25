from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .audit import scan_source_tree
from .analysis import analyze_iq
from .forensics import create_manifest, verify_manifest
from .physical import analyze_trace
from .providers import create_chat_provider
from .quantum import simulate_qubit


def _write_report(report: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)
    if output is None:
        print(rendered)
        return
    output.write_text(rendered + "\n", encoding="utf-8")
    print(f"Report written to {output}")


def _read_report(path: Path) -> dict[str, Any]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not read a valid report: {path}") from error
    if not isinstance(report, dict) or not isinstance(report.get("metrics"), dict):
        raise ValueError("Report JSON must contain a metrics object.")
    return report


def _command_analyze(args: argparse.Namespace) -> None:
    if args.output is not None and args.output.resolve() == args.iq_file.resolve():
        raise ValueError("Report output must not overwrite the IQ input file.")
    report = analyze_iq(args.iq_file, args.sample_rate)
    _write_report(report, args.output)


def _command_chat(args: argparse.Namespace) -> None:
    report = _read_report(args.report)
    provider = create_chat_provider(
        args.provider,
        args.model,
        args.base_url,
        report,
    )
    print(f"Chat ready ({args.provider}, {provider.model}). Type 'exit' to quit.")
    while True:
        try:
            question = input("iq-chat> ").strip()
        except EOFError:
            print()
            return
        if question.lower() in {"exit", "quit"}:
            return
        if question:
            print(provider.send_message(question))


def _ensure_output_distinct(output: Path | None, *inputs: Path) -> None:
    if output is not None and any(output.resolve() == path.resolve() for path in inputs):
        raise ValueError("Report output must not overwrite an input file.")


def _command_inventory(args: argparse.Namespace) -> None:
    _ensure_output_distinct(args.output)
    if args.output is not None and args.output.resolve().is_relative_to(args.root.resolve()):
        raise ValueError("Save the evidence manifest outside the evidence directory.")
    _write_report(create_manifest(args.root), args.output)


def _command_verify(args: argparse.Namespace) -> None:
    _ensure_output_distinct(args.output, args.manifest)
    if args.manifest.resolve().is_relative_to(args.root.resolve()):
        raise ValueError("Keep the evidence manifest outside the evidence directory.")
    _write_report(verify_manifest(args.root, args.manifest), args.output)


def _command_physical(args: argparse.Namespace) -> None:
    _ensure_output_distinct(args.output, args.trace, *([args.reference] if args.reference else []))
    report = analyze_trace(args.trace, args.reference, args.threshold)
    _write_report(report, args.output)


def _command_audit(args: argparse.Namespace) -> None:
    _ensure_output_distinct(args.output)
    _write_report(scan_source_tree(args.root), args.output)


def _command_quantum(args: argparse.Namespace) -> None:
    _ensure_output_distinct(args.output)
    gates = [gate.strip() for gate in args.gates.split(",") if gate.strip()]
    _write_report(simulate_qubit(gates, args.theta, args.phi), args.output)


def _interactive_menu() -> int:
    options = {
        "1": ("analyze", "IQ capture analysis"),
        "2": ("physical", "Physical measurement trace"),
        "3": ("inventory", "Create evidence manifest"),
        "4": ("verify", "Verify evidence manifest"),
        "5": ("audit", "Local source review"),
        "6": ("quantum", "Educational qubit simulation"),
        "7": ("chat", "Ask AI about a report"),
    }
    while True:
        print(
            "\nIQ Research Workbench"
            "\n1) IQ capture analysis"
            "\n2) Physical measurement trace"
            "\n3) Create evidence manifest"
            "\n4) Verify evidence manifest"
            "\n5) Local source review"
            "\n6) Educational qubit simulation"
            "\n7) Ask AI about a report"
            "\n0) Exit"
        )
        try:
            choice = input("Choose: ").strip()
            if choice in {"0", "exit", "quit"}:
                return 0
            if choice not in options:
                print("Choose a listed option.")
                continue
            command = options[choice][0]
            arguments = _menu_arguments(command)
            if arguments is not None:
                main(arguments)
        except EOFError:
            print()
            return 0
        except (OSError, ValueError) as error:
            print(f"error: {error}", file=sys.stderr)


def _menu_arguments(command: str) -> list[str] | None:
    if command == "analyze":
        path = input("IQ CSV/NPY path: ").strip()
        rate = input("Sample rate in Hz (optional): ").strip()
        return [command, path] + (["--sample-rate", rate] if rate else [])
    if command == "physical":
        path = input("Measurement CSV path: ").strip()
        reference = input("Reference CSV path (optional): ").strip()
        return [command, path] + (["--reference", reference] if reference else [])
    if command == "inventory":
        root = input("Evidence directory: ").strip()
        output = input("Manifest output path (optional): ").strip()
        return ["forensic", "inventory", root] + (["--output", output] if output else [])
    if command == "verify":
        root = input("Evidence directory: ").strip()
        manifest = input("Manifest JSON path: ").strip()
        return ["forensic", "verify", root, manifest]
    if command == "audit":
        root = input("Local source directory: ").strip()
        return [command, root]
    if command == "quantum":
        gates = input("Gate sequence, comma-separated (e.g. H,X): ").strip()
        theta = input("Initial theta in radians [0]: ").strip() or "0"
        phi = input("Initial phi in radians [0]: ").strip() or "0"
        return [command, "--gates", gates, "--theta", theta, "--phi", phi]
    if command == "chat":
        report = input("Analysis report JSON path: ").strip()
        return [command, report]
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline workbench for IQ, physical traces, evidence, local source review, and quantum education."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a CSV or NPY IQ capture.")
    analyze_parser.add_argument("iq_file", type=Path, help="CSV (I,Q) or NPY IQ file.")
    analyze_parser.add_argument(
        "--sample-rate",
        type=float,
        help="Capture sample rate in Hz; omit to report normalized frequency.",
    )
    analyze_parser.add_argument(
        "--output",
        type=Path,
        help="Write the JSON report to this path instead of stdout.",
    )
    analyze_parser.set_defaults(handler=_command_analyze)

    chat_parser = subparsers.add_parser("chat", help="Discuss a report with a supported AI provider.")
    chat_parser.add_argument("report", type=Path, help="JSON report created by analyze.")
    chat_parser.add_argument(
        "--provider",
        choices=("gemini", "openai-compatible"),
        default="gemini",
        help="AI provider (default: Gemini).",
    )
    chat_parser.add_argument("--model", help="Model name; Gemini defaults to gemini-2.5-flash.")
    chat_parser.add_argument(
        "--base-url",
        help="Base URL for an OpenAI-compatible endpoint; can also use OPENAI_COMPATIBLE_BASE_URL.",
    )
    chat_parser.set_defaults(handler=_command_chat)

    physical_parser = subparsers.add_parser(
        "physical", help="Screen a local physical measurement trace for statistical anomalies."
    )
    physical_parser.add_argument("trace", type=Path, help="CSV with measurement or time,measurement columns.")
    physical_parser.add_argument("--reference", type=Path, help="Optional reference trace for aggregate comparison.")
    physical_parser.add_argument("--threshold", type=float, default=6.0, help="Scaled-MAD outlier threshold.")
    physical_parser.add_argument("--output", type=Path, help="Write report JSON to this path.")
    physical_parser.set_defaults(handler=_command_physical)

    forensic_parser = subparsers.add_parser("forensic", help="Create or verify local evidence inventories.")
    forensic_commands = forensic_parser.add_subparsers(dest="forensic_command", required=True)
    inventory_parser = forensic_commands.add_parser("inventory", help="Hash files in an evidence directory.")
    inventory_parser.add_argument("root", type=Path, help="Evidence directory to inventory.")
    inventory_parser.add_argument("--output", type=Path, help="Write manifest JSON outside the evidence directory.")
    inventory_parser.set_defaults(handler=_command_inventory)
    verify_parser = forensic_commands.add_parser("verify", help="Compare evidence files with a saved manifest.")
    verify_parser.add_argument("root", type=Path, help="Evidence directory to verify.")
    verify_parser.add_argument("manifest", type=Path, help="Manifest JSON created by forensic inventory.")
    verify_parser.add_argument("--output", type=Path, help="Write verification report JSON to this path.")
    verify_parser.set_defaults(handler=_command_verify)

    audit_parser = subparsers.add_parser("audit", help="Run read-only static checks on local source files.")
    audit_parser.add_argument("root", type=Path, help="Local source directory; no code is executed.")
    audit_parser.add_argument("--output", type=Path, help="Write report JSON to this path.")
    audit_parser.set_defaults(handler=_command_audit)

    quantum_parser = subparsers.add_parser("quantum", help="Simulate an idealized educational single qubit.")
    quantum_parser.add_argument("--gates", default="", help="Comma-separated gates: H,X,Y,Z,S,T.")
    quantum_parser.add_argument("--theta", type=float, default=0.0, help="Initial-state theta in radians.")
    quantum_parser.add_argument("--phi", type=float, default=0.0, help="Initial-state phi in radians.")
    quantum_parser.add_argument("--output", type=Path, help="Write report JSON to this path.")
    quantum_parser.set_defaults(handler=_command_quantum)
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None and len(sys.argv) == 1:
        return _interactive_menu()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0
