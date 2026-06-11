"""Render a BlastReport: ANSI terminal report, Markdown, or JSON.

The terminal report leads with the headline — the irreversible-and-succeeded
actions — because in an incident those are the only things you can't fix by
re-running the agent. Everything below is grouped by category for context.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .models import (
    Action,
    BlastReport,
    BlastTier,
    Category,
    FileOp,
    Reversibility,
    Severity,
)

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"
_MAGENTA = "\x1b[35m"

_TIER_STYLE = {
    BlastTier.CONTAINED: (_GREEN, "CONTAINED"),
    BlastTier.MODERATE: (_YELLOW, "MODERATE"),
    BlastTier.WIDE: (_RED, "WIDE"),
    BlastTier.CRITICAL: (_RED, "CRITICAL"),
}

_SEVERITY_STYLE = {
    Severity.CRITICAL: (_RED, "CRIT"),
    Severity.HIGH: (_RED, "HIGH"),
    Severity.MEDIUM: (_YELLOW, "MED"),
    Severity.LOW: (_DIM, "LOW"),
    Severity.INFO: (_DIM, "INFO"),
}

_REV_LABEL = {
    Reversibility.REVERSIBLE: "reversible",
    Reversibility.HARD_TO_REVERSE: "hard-to-reverse",
    Reversibility.IRREVERSIBLE: "IRREVERSIBLE",
}

_CATEGORY_LABEL = {
    Category.FILES: "Files",
    Category.VCS: "Version control",
    Category.NETWORK: "Network / external",
    Category.PACKAGES: "Packages / env",
    Category.SYSTEM: "System / destructive",
    Category.SECRETS: "Secrets surface",
}

_FILEOP_LABEL = {
    FileOp.CREATED: "created",
    FileOp.MODIFIED: "modified",
    FileOp.DELETED: "deleted",
    FileOp.MOVED: "moved",
}


def _colors_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, *styles: str, enabled: bool = True) -> str:
    if not enabled or not styles:
        return text
    return "".join(styles) + text + _RESET


def _short(text: str, width: int = 88) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"


def render_terminal(report: BlastReport, color: bool | None = None) -> str:
    color = _colors_enabled() if color is None else color
    session = report.session
    lines: list[str] = []
    out = lines.append

    title = session.slug or Path(session.path).stem[:12]
    out("")
    out(_paint("  agent-blast-radius", _BOLD, _CYAN, enabled=color)
        + _paint(" — what did this agent touch, and what's irreversible?",
                 _DIM, enabled=color))
    out(_paint(f"  session {title} · {len(session.events)} events"
               + (f" · {session.cwd}" if session.cwd else ""),
               _DIM, enabled=color))
    out("")

    tier_style, tier_label = _TIER_STYLE[report.tier]
    out(f"  {_paint('BLAST TIER', _BOLD, enabled=color)}  "
        + _paint(tier_label, _BOLD, tier_style, enabled=color))
    counts = report.counts()
    summary = " · ".join(f"{counts[c.value]} {c.value}" for c in Category
                         if counts[c.value])
    out(_paint("  " + (summary or "no side-effecting actions detected"),
               _DIM, enabled=color))
    out("")

    headlines = report.headlines()
    out(_paint("  IRREVERSIBLE & SUCCEEDED", _BOLD,
               _RED if headlines else _DIM, enabled=color)
        + _paint(f"  ({len(headlines)})", _DIM, enabled=color))
    if headlines:
        for action in headlines:
            sev_style, sev_label = _SEVERITY_STYLE[action.severity]
            out(f"  {_paint('● ' + sev_label.ljust(4), sev_style, _BOLD, enabled=color)}"
                f" {_short(action.target)}")
            out(_paint(f"    └─ {action.detail}  [event {action.event_index}]",
                       _DIM, enabled=color))
    else:
        out(_paint("  none — nothing the agent did is unrecoverable.",
                   _DIM, enabled=color))
    out("")

    grouped = report.by_category()
    for category in Category:
        items = grouped[category]
        if not items:
            continue
        out(_paint(f"  {_CATEGORY_LABEL[category].upper()}", _BOLD, enabled=color)
            + _paint(f"  ({len(items)})", _DIM, enabled=color))
        for action in items:
            out("  " + _format_action_line(action, color))
        out("")

    return "\n".join(lines)


def _format_action_line(action: Action, color: bool) -> str:
    sev_style, sev_label = _SEVERITY_STYLE[action.severity]
    mark = "✓" if action.succeeded else "✗"
    mark_style = _GREEN if action.succeeded else _RED
    op = ""
    if action.file_op is not None:
        op = _paint(f"[{_FILEOP_LABEL[action.file_op]}", _DIM, enabled=color)
        if action.edit_count > 1 and action.file_op is FileOp.MODIFIED:
            op += _paint(f" ×{action.edit_count}", _DIM, enabled=color)
        op += _paint("] ", _DIM, enabled=color)
    rev = _paint(_REV_LABEL[action.reversibility],
                 _MAGENTA if action.reversibility is Reversibility.IRREVERSIBLE else _DIM,
                 enabled=color)
    escape = _paint(" ⚠path-escape", _RED, enabled=color) if action.path_escape else ""
    return (f"{_paint(mark, mark_style, enabled=color)} "
            f"{_paint(sev_label.ljust(4), sev_style, enabled=color)} "
            f"{op}{_short(action.target, 70)}  "
            f"{rev}{escape}")


# --- JSON ----------------------------------------------------------------

def _action_dict(action: Action) -> dict:
    return {
        "category": action.category.value,
        "target": action.target,
        "raw": action.raw,
        "event_index": action.event_index,
        "reversibility": action.reversibility.value,
        "severity": action.severity.value,
        "succeeded": action.succeeded,
        "detail": action.detail,
        "file_op": action.file_op.value if action.file_op else None,
        "edit_count": action.edit_count,
        "path_escape": action.path_escape,
        "headline": action.is_headline(),
    }


def render_json(report: BlastReport) -> str:
    return json.dumps({
        "transcript": report.session.path,
        "session_id": report.session.session_id,
        "cwd": report.session.cwd,
        "tier": report.tier.value,
        "counts": report.counts(),
        "headlines": [_action_dict(a) for a in report.headlines()],
        "actions": [_action_dict(a) for a in report.actions],
    }, indent=2)


# --- Markdown ------------------------------------------------------------

def render_markdown(report: BlastReport) -> str:
    session = report.session
    lines = [
        "# agent-blast-radius report",
        "",
        f"- **Transcript:** `{Path(session.path).name}`",
        f"- **Project:** `{session.cwd or 'unknown'}`",
        f"- **Blast tier:** {report.tier.value.upper()}",
        "",
        "## Irreversible & succeeded",
        "",
    ]
    headlines = report.headlines()
    if headlines:
        lines += ["| Severity | Action | Why | Event |", "|---|---|---|---|"]
        for a in headlines:
            lines.append(
                f"| {a.severity.value.upper()} | `{_md(a.target)}` "
                f"| {_md(a.detail)} | {a.event_index} |")
    else:
        lines.append("_None — nothing the agent did is unrecoverable._")
    lines.append("")

    grouped = report.by_category()
    for category in Category:
        items = grouped[category]
        if not items:
            continue
        lines += [f"## {_CATEGORY_LABEL[category]}", "",
                  "| ✓ | Severity | Target | Reversibility | Why | Event |",
                  "|---|---|---|---|---|---|"]
        for a in items:
            mark = "✓" if a.succeeded else "✗"
            lines.append(
                f"| {mark} | {a.severity.value.upper()} | `{_md(a.target)}` "
                f"| {a.reversibility.value} | {_md(a.detail)} | {a.event_index} |")
        lines.append("")
    return "\n".join(lines)


def _md(text: str) -> str:
    return _short(text, 120).replace("|", "\\|").replace("`", "'")
