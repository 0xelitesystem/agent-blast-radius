"""Data models for agent-blast-radius.

The forensic pipeline reasons about a few shapes: a Session is an ordered
list of Events (assistant text or tool calls) parsed from the transcript;
extract.py turns side-effecting Events into Actions; classify.py stamps each
Action with a Reversibility and a Severity; the whole thing rolls up into a
BlastReport with a single BlastTier headline.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class EventKind(enum.Enum):
    TEXT = "text"
    TOOL_CALL = "tool_call"


@dataclass
class Event:
    """One thing that happened in the session, in transcript order."""

    kind: EventKind
    index: int  # position in the session event stream
    timestamp: str = ""
    is_sidechain: bool = False

    # TEXT events
    text: str = ""

    # TOOL_CALL events
    tool_name: str = ""
    tool_id: str = ""
    tool_input: dict = field(default_factory=dict)
    output: str = ""
    is_error: bool = False
    exit_code: int | None = None

    @property
    def command(self) -> str:
        """Shell command for Bash/PowerShell calls, else empty."""
        if self.tool_name in ("Bash", "PowerShell"):
            return str(self.tool_input.get("command", ""))
        return ""

    @property
    def file_path(self) -> str:
        """Target path for file-mutating tools, else empty."""
        return str(self.tool_input.get("file_path", ""))

    def is_file_edit(self) -> bool:
        return self.tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit")

    def succeeded(self) -> bool:
        """Did this tool call actually run its side effect?

        A command that errored (is_error, or a non-zero exit code parsed
        from output) never had its effect — a failed `rm` deleted nothing.
        When we have no result at all we assume success: the absence of an
        error record is weak evidence the call went through.
        """
        if self.is_error:
            return False
        if self.exit_code is not None:
            return self.exit_code == 0
        return True


@dataclass
class Session:
    """A parsed agent session transcript."""

    path: str
    session_id: str = ""
    cwd: str = ""
    git_branch: str = ""
    slug: str = ""
    version: str = ""
    events: list[Event] = field(default_factory=list)
    first_timestamp: str = ""
    last_timestamp: str = ""

    def tool_calls(self) -> list[Event]:
        return [e for e in self.events if e.kind is EventKind.TOOL_CALL]

    def text_events(self) -> list[Event]:
        return [e for e in self.events if e.kind is EventKind.TEXT]


class Category(enum.Enum):
    """The five blast-radius surfaces an action can land on, plus secrets."""

    FILES = "files"
    VCS = "vcs"
    NETWORK = "network"
    PACKAGES = "packages"
    SYSTEM = "system"
    SECRETS = "secrets"


class Reversibility(enum.Enum):
    """How hard it is to undo an action — the core forensic axis.

    Ordered worst-last so max() finds the most permanent action.
    """

    REVERSIBLE = "reversible"  # ctrl-Z territory: an edit, a local commit
    HARD_TO_REVERSE = "hard_to_reverse"  # recoverable with effort: rm a file, reset --hard
    IRREVERSIBLE = "irreversible"  # gone: pushed to remote, data egressed, force-pushed


_REVERSIBILITY_RANK = {
    Reversibility.REVERSIBLE: 0,
    Reversibility.HARD_TO_REVERSE: 1,
    Reversibility.IRREVERSIBLE: 2,
}


class Severity(enum.Enum):
    """Danger ranking, independent of reversibility (a noisy `curl` GET is
    reversible but its egress can still be HIGH). Ordered worst-last."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(sev: Severity) -> int:
    return _SEVERITY_RANK[sev]


def reversibility_rank(rev: Reversibility) -> int:
    return _REVERSIBILITY_RANK[rev]


class FileOp(enum.Enum):
    """What happened to a file — created / modified / deleted / moved."""

    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"


@dataclass
class Action:
    """One side-effecting thing the agent did, classified for the report.

    `target` is the human-facing subject: a file path, a command, a URL.
    `raw` is the exact command or tool input we reconstructed it from, so a
    reader can always trace a verdict back to a line in the transcript.
    """

    category: Category
    target: str
    raw: str  # the literal command / file_path the action came from
    event_index: int
    reversibility: Reversibility
    severity: Severity
    succeeded: bool
    detail: str = ""  # one-line "why this severity" explanation
    file_op: FileOp | None = None  # set for FILES actions
    edit_count: int = 1  # how many edits this file accumulated (FILES)
    path_escape: bool = False  # target resolved outside session.cwd

    def is_headline(self) -> bool:
        """Irreversible AND it actually happened — the can't-take-it-back set."""
        return self.succeeded and self.reversibility is Reversibility.IRREVERSIBLE


class BlastTier(enum.Enum):
    """Session-level summary of the worst successful damage done."""

    CONTAINED = "contained"  # edits, local commits — all recoverable
    MODERATE = "moderate"  # deletes / installs / resets — recoverable with effort
    WIDE = "wide"  # an irreversible action landed (push, egress)
    CRITICAL = "critical"  # an irreversible action AND it was CRITICAL severity


@dataclass
class BlastReport:
    """Everything the analysis produced for one session."""

    session: Session
    actions: list[Action] = field(default_factory=list)
    tier: BlastTier = BlastTier.CONTAINED

    def by_category(self) -> dict[Category, list[Action]]:
        grouped: dict[Category, list[Action]] = {c: [] for c in Category}
        for action in self.actions:
            grouped[action.category].append(action)
        return grouped

    def headlines(self) -> list[Action]:
        """Irreversible, successful actions — sorted most dangerous first."""
        heads = [a for a in self.actions if a.is_headline()]
        heads.sort(key=lambda a: severity_rank(a.severity), reverse=True)
        return heads

    def counts(self) -> dict[str, int]:
        return {c.value: len(v) for c, v in self.by_category().items()}
