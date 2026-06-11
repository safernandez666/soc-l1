"""Command-line entrypoint for CleanSwarm.

Example:
    python -m src.cleanswarm analyze --alerts-path /var/ossec/logs/alerts/alerts.json --out report.json
"""
from __future__ import annotations

import argparse
from pathlib import Path

from src.cleanswarm.report import analyze_file, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cleanswarm", description="Wazuh hygiene analyzer")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a Wazuh alerts.json NDJSON file")
    analyze.add_argument("--alerts-path", default="/var/ossec/logs/alerts/alerts.json")
    analyze.add_argument("--days", type=int, default=7)
    analyze.add_argument("--min-count", type=int, default=10)
    analyze.add_argument("--top", type=int, default=20)
    analyze.add_argument("--max-recommendations", type=int, default=10)
    analyze.add_argument("--limit", type=int, default=None)
    analyze.add_argument("--format", choices=("json", "markdown"), default="json")
    analyze.add_argument("--out", default="", help="Write report to path instead of stdout")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        report = analyze_file(
            args.alerts_path,
            days=args.days,
            min_count=args.min_count,
            top=args.top,
            max_recommendations=args.max_recommendations,
            limit=args.limit,
        )
        output = (
            report.model_dump_json(indent=2)
            if args.format == "json"
            else render_markdown(report)
        )
        if args.out:
            Path(args.out).write_text(output, encoding="utf-8")
        else:
            print(output)
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
