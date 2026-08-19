"""Classification: success-gating downgrade, and tier rollup."""

from __future__ import annotations

from agent_blast_radius.classify import analyze, compute_tier
from agent_blast_radius.models import (
    BlastTier,
    FileOp,
    Reversibility,
    Severity,
)
from agent_blast_radius.parser import parse_transcript


def _report(path):
    return analyze(parse_transcript(path))


def test_benign_is_contained(benign_transcript):
    assert _report(benign_transcript).tier is BlastTier.CONTAINED


def test_destructive_is_wide(destructive_transcript):
    # git push (irreversible HIGH) + rm -rf, no CRITICAL irreversible -> WIDE.
    assert _report(destructive_transcript).tier is BlastTier.WIDE


def test_critical_is_critical(critical_transcript):
    # force-push is irreversible + CRITICAL -> CRITICAL tier.
    assert _report(critical_transcript).tier is BlastTier.CRITICAL


def test_db_delete_is_critical(db_transcript):
    assert _report(db_transcript).tier is BlastTier.CRITICAL


def test_failed_delete_does_not_count(failed_delete_transcript):
    report = _report(failed_delete_transcript)
    # The rm failed -> tier must stay CONTAINED (nothing was deleted).
    assert report.tier is BlastTier.CONTAINED
    deletes = [a for a in report.actions if a.file_op is FileOp.DELETED]
    assert deletes  # the action is still recorded...
    assert not deletes[0].succeeded  # ...but marked failed...
    # ...and downgraded so it can't drive the tier.
    assert deletes[0].reversibility is Reversibility.REVERSIBLE
    assert deletes[0].severity is Severity.LOW
    assert "failed" in deletes[0].detail


def test_failed_critical_does_not_escalate(tmp_path):
    """A force-push that FAILS must not produce a CRITICAL tier."""
    from tests.conftest import bash, tool_result, write_jsonl
    records = [
        bash("a", "git push --force origin main"),
        tool_result("a", "error: failed to push some refs", is_error=True),
    ]
    p = write_jsonl(tmp_path / "failpush.jsonl", records)
    report = _report(p)
    assert report.tier is BlastTier.CONTAINED


def test_only_install_is_moderate(tmp_path):
    """A successful local pip install (hard-to-reverse, not irreversible) -> MODERATE."""
    from tests.conftest import bash, tool_result, write_jsonl
    records = [
        bash("a", "pip install requests"),
        tool_result("a", "Successfully installed requests-2.0"),
    ]
    p = write_jsonl(tmp_path / "install.jsonl", records)
    assert _report(p).tier is BlastTier.MODERATE


def test_headlines_are_irreversible_and_succeeded(critical_transcript):
    report = _report(critical_transcript)
    heads = report.headlines()
    assert heads
    assert all(a.is_headline() for a in heads)
    # Sorted most dangerous first.
    assert heads[0].severity is Severity.CRITICAL


def test_compute_tier_empty():
    assert compute_tier([]) is BlastTier.CONTAINED


def test_headline_excludes_failed(failed_delete_transcript):
    report = _report(failed_delete_transcript)
    assert report.headlines() == []
