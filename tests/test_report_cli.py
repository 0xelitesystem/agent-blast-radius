"""Report rendering (terminal/json/md) and the CLI surface (flags, exit codes)."""

from __future__ import annotations

import json

from agent_blast_radius.classify import analyze
from agent_blast_radius.cli import main
from agent_blast_radius.parser import parse_transcript
from agent_blast_radius.report import render_json, render_markdown, render_terminal


def _report(path):
    return analyze(parse_transcript(path))


# --- rendering -----------------------------------------------------------

def test_terminal_shows_tier_and_headline(critical_transcript):
    text = render_terminal(_report(critical_transcript), color=False)
    assert "BLAST TIER" in text
    assert "CRITICAL" in text
    assert "IRREVERSIBLE & SUCCEEDED" in text


def test_terminal_no_color_has_no_ansi(benign_transcript):
    text = render_terminal(_report(benign_transcript), color=False)
    assert "\x1b[" not in text


def test_json_is_valid_and_complete(destructive_transcript):
    data = json.loads(render_json(_report(destructive_transcript)))
    assert data["tier"] == "wide"
    assert "actions" in data and data["actions"]
    assert "headlines" in data
    assert any(a["category"] == "vcs" for a in data["actions"])


def test_markdown_has_sections(critical_transcript):
    md = render_markdown(_report(critical_transcript))
    assert "# agent-blast-radius report" in md
    assert "Irreversible & succeeded" in md


# --- cli -----------------------------------------------------------------

def test_cli_report_runs(benign_transcript, capsys):
    rc = main(["report", benign_transcript, "--no-color"])
    assert rc == 0
    assert "CONTAINED" in capsys.readouterr().out


def test_cli_json_flag(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tier"] == "wide"


def test_cli_fail_on_critical_exits_1(critical_transcript, capsys):
    rc = main(["report", critical_transcript, "--no-color", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 1


def test_cli_fail_on_critical_passes_when_clean(benign_transcript, capsys):
    rc = main(["report", benign_transcript, "--no-color", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 0


def test_cli_only_filter(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--no-color", "--only", "vcs"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERSION CONTROL" in out
    # SYSTEM section (the rm -rf) should be filtered out of the view.
    assert "SYSTEM / DESTRUCTIVE" not in out


def test_cli_only_filter_json(destructive_transcript, capsys):
    rc = main(["report", destructive_transcript, "--json", "--only", "vcs"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert all(a["category"] == "vcs" for a in data["actions"])


def test_cli_danger_min_filter(critical_transcript, capsys):
    rc = main(["report", critical_transcript, "--json", "--danger-min", "high"])
    data = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert data["actions"]
    assert all(a["severity"] in ("high", "critical") for a in data["actions"])


def test_cli_filter_does_not_change_gate(critical_transcript, capsys):
    """Filtering the view to 'files' must still let --fail-on-critical fire on
    the force-push that's no longer shown."""
    rc = main(["report", critical_transcript, "--no-color",
               "--only", "files", "--fail-on-critical"])
    capsys.readouterr()
    assert rc == 1


def test_cli_md_writes_file(benign_transcript, tmp_path, capsys):
    out_md = tmp_path / "out.md"
    rc = main(["report", benign_transcript, "--no-color", "--md", str(out_md)])
    capsys.readouterr()
    assert rc == 0
    assert out_md.exists()
    assert "agent-blast-radius report" in out_md.read_text(encoding="utf-8")


def test_cli_missing_target_exits_2(capsys):
    rc = main(["report", "definitely-not-a-real-target-xyz"])
    capsys.readouterr()
    assert rc == 2


def test_cli_version(capsys):
    import pytest
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "blast-radius" in capsys.readouterr().out
