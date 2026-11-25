from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .analysis import analyze_iq
from .providers import create_chat_provider


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline IQ signal characterization with optional AI report chat."
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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0
