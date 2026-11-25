"""Command-line interface for SentinelTrace."""

import argparse
import json
import sys
from pathlib import Path

from sentineltrace.engine import analyze_events
from sentineltrace.parser import load_events
from sentineltrace.reporter import (
    write_json_report,
    write_markdown_report,
)


def run_command(args: argparse.Namespace) -> int:
    try:
        events, errors = load_events(args.input)

        print(f"[INFO] Events successfully parsed: {len(events)}")
        print(f"[INFO] Records rejected: {len(errors)}")

        findings = analyze_events(events)

        json_path = write_json_report(findings, args.out)
        markdown_path = write_markdown_report(findings, args.out)

        print(f"[INFO] Findings generated: {len(findings)}")
        print(f"[INFO] JSON report: {json_path}")
        print(f"[INFO] Markdown report: {markdown_path}")

        if errors:
            error_path = Path(args.out) / "parser_errors.json"
            error_path.write_text(
                json.dumps(errors, indent=2),
                encoding="utf-8",
            )
            print(f"[WARNING] Parser errors saved: {error_path}")

        return 0

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentineltrace",
        description="Evidence-based SOC investigation engine",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="Analyze security events and generate investigation reports",
    )

    run_parser.add_argument(
        "--input",
        required=True,
        help="Path to JSON or JSONL event file",
    )

    run_parser.add_argument(
        "--out",
        default="reports",
        help="Output directory (default: reports)",
    )

    args = parser.parse_args()

    if args.command == "run":
        sys.exit(run_command(args))


if __name__ == "__main__":
    main()
