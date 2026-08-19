"""Refine Action severity/reversibility and compute the session blast tier.

extract.py already sets a first-pass severity and reversibility per action
from its command shape. This module applies the two cross-cutting policies
that need the whole picture:

1. Success-gating downgrade. A *failed* destructive command did nothing.
   `rm important.py` that exited non-zero deleted no file. We must not let a
   failed action drive the tier, so we neutralize its blast (severity floored,
   reversibility relaxed) while keeping the record visible with a "(failed)"
   note. This is the single most important correctness rule in the tool.

2. Tier rollup. The session tier is the worst SUCCESSFUL damage:
   CRITICAL only if some successful action is both IRREVERSIBLE and CRITICAL;
   WIDE if any successful IRREVERSIBLE action landed; MODERATE if anything
   hard-to-reverse succeeded; CONTAINED otherwise (only reversible edits).
"""

from __future__ import annotations

from .models import (
    Action,
    BlastReport,
    BlastTier,
    FileOp,
    Reversibility,
    Session,
    Severity,
    reversibility_rank,
    severity_rank,
)


def classify_actions(actions: list[Action]) -> list[Action]:
    """Apply per-action refinements in place and return the list."""
    for action in actions:
        _refine(action)
        if not action.succeeded:
            _downgrade_failed(action)
    return actions


def _refine(action: Action) -> None:
    """Second-pass nudges that depend on accumulated fields (edit_count,
    path_escape) rather than just the command verb."""
    # A file written/edited many times is still reversible, but a path that
    # escaped the cwd is a real blast-radius concern regardless of op.
    if action.path_escape and action.severity is Severity.INFO:
        action.severity = Severity.MEDIUM
        action.detail = (action.detail + ", wrote outside cwd").strip(" ,")
    # Heavily-edited files are worth surfacing but stay reversible/LOW.
    if action.file_op is FileOp.MODIFIED and action.edit_count >= 5 \
            and action.severity is Severity.INFO:
        action.severity = Severity.LOW


def _downgrade_failed(action: Action) -> None:
    """A command that did not succeed had no side effect. Neutralize its
    blast so it can never raise the tier, but keep it in the report (an agent
    *attempting* `rm -rf /` is still worth seeing, just not as damage done)."""
    action.reversibility = Reversibility.REVERSIBLE
    if severity_rank(action.severity) > severity_rank(Severity.LOW):
        action.severity = Severity.LOW
    if action.detail and "(failed" not in action.detail:
        action.detail = f"{action.detail} (failed, no effect)"
    elif not action.detail:
        action.detail = "failed, no effect"


def compute_tier(actions: list[Action]) -> BlastTier:
    """Roll the classified actions up to one session-level tier.

    Only SUCCESSFUL actions count toward damage. A failed destructive call
    took no effect (see _downgrade_failed). We look at the worst combination
    of reversibility and severity among the survivors.
    """
    successful = [a for a in actions if a.succeeded]
    if not successful:
        return BlastTier.CONTAINED

    worst_rev = max((a.reversibility for a in successful),
                    key=reversibility_rank, default=Reversibility.REVERSIBLE)

    irreversible = [a for a in successful
                    if a.reversibility is Reversibility.IRREVERSIBLE]
    if irreversible:
        worst_irrev_sev = max((a.severity for a in irreversible), key=severity_rank)
        if worst_irrev_sev is Severity.CRITICAL:
            return BlastTier.CRITICAL
        return BlastTier.WIDE

    if worst_rev is Reversibility.HARD_TO_REVERSE:
        return BlastTier.MODERATE

    return BlastTier.CONTAINED


def analyze(session: Session) -> BlastReport:
    """Full pipeline tail: extract → classify → tier. Imported lazily to
    avoid a circular import (extract imports models; classify imports extract
    would otherwise loop through report)."""
    from .extract import extract_actions

    actions = classify_actions(extract_actions(session))
    return BlastReport(
        session=session,
        actions=actions,
        tier=compute_tier(actions),
    )
