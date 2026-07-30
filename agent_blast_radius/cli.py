"""blast-radius: reconstruct what an agent session touched, from the transcript.

Usage:
  blast-radius report <transcript.jsonl | session-id-prefix | latest> [options]
  blast-radius list [--project NAME] [--limit N]

Options:
  --project NAME       only consider transcripts whose project folder matches
  --json               emit machine-readable JSON instead of the terminal report
  --md FILE            also write a Markdown report to FILE
  --no-color           disable ANSI colors
  --only CATEGORY      show only one surface (files/vcs/network/packages/system/secrets)
  --danger-min LEVEL   hide actions below this severity (info/low/medium/high/critical)
  --fail-on-critical   exit 1 if any successful action is IRREVERSIBLE + CRITICAL (CI gate)
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .classify import analyze
from .models import (
    BlastReport,
    Category,
    Reversibility,
    Severity,
    severity_rank,
)
from .parser import discover_transcripts, parse_transcript, resolve_target
from .report import render_json, render_markdown, render_terminal

_SEVERITY_BY_NAME = {s.value: s for s in Severity}
_CATEGORY_BY_NAME = {c.value: c for c in Category}


def analyze_transcript(target: str, project: str | None = None) -> BlastReport:
    """Library entry point: resolve a target, parse it, return the report."""
    path = resolve_target(target, project)
    session = parse_transcript(path)
    return analyze(session)


def _filtered(report: BlastReport, only: str | None,
              danger_min: str | None) -> BlastReport:
    """Return a shallow copy of the report with actions filtered by the
    --only / --danger-min flags. Tier is computed from the *full* action set
    and left untouched: filters change the view, not the verdict."""
    actions = report.actions
    if only:
        category = _CATEGORY_BY_NAME[only]
        actions = [a for a in actions if a.category is category]
    if danger_min:
        floor = severity_rank(_SEVERITY_BY_NAME[danger_min])
        actions = [a for a in actions if severity_rank(a.severity) >= floor]
    return BlastReport(session=report.session, actions=actions, tier=report.tier)


def _has_critical_irreversible(report: BlastReport) -> bool:
    """The --fail-on-critical condition: a successful action that is both
    IRREVERSIBLE and CRITICAL (force-push, destructive SQL that landed)."""
    return any(
        a.succeeded
        and a.reversibility is Reversibility.IRREVERSIBLE
        and a.severity is Severity.CRITICAL
        for a in report.actions
    )


def _cmd_report(args: argparse.Namespace) -> int:
    try:
        report = analyze_transcript(args.target, args.project)
    except FileNotFoundError as exc:
        print(f"blast-radius: {exc}", file=sys.stderr)
        return 2

    view = _filtered(report, args.only, args.danger_min)

    if args.json:
        print(render_json(view))
    else:
        color = False if args.no_color else None
        print(render_terminal(view, color=color))

    if args.md:
        Path(args.md).write_text(render_markdown(view), encoding="utf-8")
        if not args.json:
            print(f"  markdown report written to {args.md}\n")

    # The gate inspects the *unfiltered* report. A CRITICAL action you
    # filtered out of the view is still a CRITICAL action that happened.
    if args.fail_on_critical and _has_critical_irreversible(report):
        return 1
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    transcripts = discover_transcripts(args.project)[: args.limit]
    if not transcripts:
        print("no transcripts found under ~/.claude/projects", file=sys.stderr)
        return 2
    for path in transcripts:
        mtime = datetime.fromtimestamp(path.stat().st_mtime)
        size_kb = path.stat().st_size // 1024
        print(f"{path.stem[:8]}  {mtime:%Y-%m-%d %H:%M}  {size_kb:>6} KB  "
              f"{path.parent.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blast-radius",
        description="Reconstruct what an agent session touched, and what's "
                    "irreversible, from its transcript.",
    )
    parser.add_argument("--version", action="version",
                        version=f"blast-radius {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    rep = sub.add_parser("report", help="analyze one session transcript")
    rep.add_argument("target", help="transcript path, session-id prefix, or 'latest'")
    rep.add_argument("--project", help="filter session discovery by project name")
    rep.add_argument("--json", action="store_true", help="JSON output")
    rep.add_argument("--md", metavar="FILE", help="write Markdown report to FILE")
    rep.add_argument("--no-color", action="store_true", help="plain output")
    rep.add_argument("--only", choices=sorted(_CATEGORY_BY_NAME),
                     help="show only one surface")
    rep.add_argument("--danger-min", choices=[s.value for s in Severity],
                     help="hide actions below this severity")
    rep.add_argument("--fail-on-critical", action="store_true",
                     help="exit 1 if any successful action is irreversible + critical")
    rep.set_defaults(func=_cmd_report)

    lst = sub.add_parser("list", help="list recent session transcripts")
    lst.add_argument("--project", help="filter by project folder name")
    lst.add_argument("--limit", type=int, default=15)
    lst.set_defaults(func=_cmd_list)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Windows consoles often default to cp1252, which can't encode the ✓/✗/●/⚠
    # glyphs or the ── box-drawing we print. Reconfigure to utf-8 with
    # errors=replace so a forensic report never dies on an encode error mid-run
    # (a crash here would defeat the whole point: you run this *after* an
    # incident, when you least want a second failure).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
