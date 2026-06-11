"""Turn parsed Events into side-effecting Action records.

This module is the forensic reconstruction step: walk the tool calls in
transcript order and emit one Action per observable side effect. We work
purely from the transcript — no live process tracing — so everything here
is pattern-matching on tool names and shell command text. classify.py then
stamps each Action with reversibility + severity; we only set the raw facts
(category, target, success, file_op, path_escape, edit_count) here.

Why split extract from classify: extraction is "what happened" (stable,
mechanical), classification is "how bad is it" (a policy that may evolve).
Keeping them apart means we can tune severities without touching parsing.
"""

from __future__ import annotations

import re
import shlex
from pathlib import PureWindowsPath

from .models import (
    Action,
    Category,
    Event,
    EventKind,
    FileOp,
    Reversibility,
    Session,
    Severity,
)

# --- file-mutating tools -------------------------------------------------

# Tools that write to a single file_path. We treat them as edits/creates and
# decide created-vs-modified by whether we've seen the path before in-session.
_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

# --- shell command recognizers ------------------------------------------
# Each regex matches the *start* of a command token sequence. We tokenize
# with shlex first (POSIX rules) so flags and quoting don't fool us, then
# fall back to substring checks for shapes shlex can't safely split.

# File deletion / move via shell.
_RM_RE = re.compile(r"^(rm|del|erase|unlink)$", re.IGNORECASE)
_PS_REMOVE_RE = re.compile(r"^Remove-Item$", re.IGNORECASE)
_MV_RE = re.compile(r"^(mv|move)$", re.IGNORECASE)
_PS_MOVE_RE = re.compile(r"^Move-Item$", re.IGNORECASE)

# Recursive/force flags that make a delete a wide blast.
_RECURSIVE_FLAGS = ("-r", "-rf", "-fr", "-rf,", "--recursive", "-recurse")
_FORCE_FLAGS = ("-f", "--force", "-force")

# Network egress / fetch.
_NET_TOOLS = ("WebFetch", "WebSearch")
_CURL_RE = re.compile(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b",
                      re.IGNORECASE)
_POST_RE = re.compile(
    r"(-X\s*POST|--data\b|--data-raw\b|-d\s|--form\b|-F\s|-Method\s+POST|"
    r"--upload-file|-T\s|-Body\b)", re.IGNORECASE)

# Package managers.
_PKG_RE = re.compile(
    r"\b(pip|pip3|npm|yarn|pnpm|cargo|apt|apt-get|brew|uv|gem|go|poetry)\b",
    re.IGNORECASE)
_PKG_INSTALL_WORDS = ("install", "add", "get")
_GLOBAL_FLAGS = ("-g", "--global", "--system", "sudo")

# Secrets surface — reading credential material.
_SECRET_NAME_RE = re.compile(
    r"(\.env|\.envrc|credentials|secret|\.pem|\.key|id_rsa|id_ed25519|"
    r"\.aws/|\.ssh/|\.netrc|token|\.pgpass|kube.*config|\.npmrc)",
    re.IGNORECASE)
_READ_CMDS = ("cat", "type", "less", "more", "head", "tail", "Get-Content", "gc")

# System / destructive.
_CHMOD_RE = re.compile(r"^(chmod|chown|icacls|Set-Acl)$", re.IGNORECASE)
_KILL_RE = re.compile(r"^(kill|pkill|killall|Stop-Process|taskkill)$", re.IGNORECASE)
_DOCKER_RE = re.compile(r"^docker$", re.IGNORECASE)
_SYSTEMCTL_RE = re.compile(r"^(systemctl|service|launchctl|sc)$", re.IGNORECASE)
_CRON_RE = re.compile(r"\b(crontab|schtasks|Register-ScheduledTask|at)\b",
                      re.IGNORECASE)
_DB_CLI_RE = re.compile(r"\b(psql|mysql|sqlite3|mongo|redis-cli)\b", re.IGNORECASE)
_DB_DESTRUCTIVE_RE = re.compile(
    r"\b(DROP\s+(TABLE|DATABASE|SCHEMA)|DELETE\s+FROM|TRUNCATE|"
    r"UPDATE\s+\w+\s+SET|ALTER\s+TABLE)\b", re.IGNORECASE)
_MIGRATE_RE = re.compile(
    r"\b(migrate|migration|alembic\s+upgrade|flyway|prisma\s+migrate|"
    r"rails\s+db:migrate|knex\s+migrate)\b", re.IGNORECASE)

# Version control — the highest-stakes category.
_GIT_RE = re.compile(r"^git$", re.IGNORECASE)
_GH_RE = re.compile(r"^gh$", re.IGNORECASE)
_GH_WRITE_SUBS = ("pr", "issue", "repo", "release", "api", "gist", "secret")
_GH_WRITE_VERBS = ("create", "delete", "edit", "merge", "close", "comment",
                   "transfer", "rename")


def _tokens(command: str) -> list[str]:
    """Best-effort shell tokenization. shlex is POSIX; Windows paths with
    backslashes confuse it, so we fall back to a naive split on failure.
    We only need the leading verb/flag shape, not perfect fidelity."""
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _split_pipeline(command: str) -> list[str]:
    """Break a command line into segments at ; && || | so we classify each
    sub-command (an agent often chains `git add . && git commit && git push`)."""
    return [seg.strip() for seg in re.split(r"&&|\|\||[;|]", command) if seg.strip()]


def _path_escapes(path: str, cwd: str) -> bool:
    """True when `path` resolves outside the session cwd — a write/delete
    that reaches beyond the project the agent was supposed to be working in.
    Done lexically (no disk touch): forensic input may be on another machine."""
    if not path or not cwd:
        return False
    try:
        # PureWindowsPath handles both / and \ and drive letters; it also
        # accepts POSIX-looking paths, so it's the safe common denominator
        # for transcripts captured on either OS.
        p = PureWindowsPath(path)
        base = PureWindowsPath(cwd)
    except Exception:
        return False
    if not p.is_absolute():
        return False  # relative path is assumed inside cwd
    try:
        p_parts = [s.lower() for s in p.parts]
        base_parts = [s.lower() for s in base.parts]
    except Exception:
        return False
    if len(p_parts) < len(base_parts):
        return True
    return p_parts[: len(base_parts)] != base_parts


def _strip_quotes(token: str) -> str:
    return token.strip().strip("'\"")


def extract_actions(session: Session) -> list[Action]:
    """Walk the session and produce one Action per side effect, in order."""
    actions: list[Action] = []
    seen_paths: dict[str, int] = {}  # normalized path -> count of edits so far

    for event in session.events:
        if event.kind is not EventKind.TOOL_CALL:
            continue
        if event.tool_name in _FILE_TOOLS:
            _extract_file_tool(event, session, actions, seen_paths)
        elif event.tool_name in _NET_TOOLS:
            actions.append(_net_tool_action(event))
        elif event.tool_name in ("Bash", "PowerShell"):
            _extract_shell(event, session, actions, seen_paths)
        # Read of a secret file is an exposure even though it's not a mutation.
        if event.tool_name == "Read":
            secret = _maybe_secret_read(event)
            if secret is not None:
                actions.append(secret)

    return actions


# --- file tools ----------------------------------------------------------

def _norm(path: str) -> str:
    return path.replace("\\", "/").rstrip("/").lower()


def _extract_file_tool(event, session, actions, seen_paths) -> None:
    path = event.file_path
    if not path:
        return
    key = _norm(path)
    # Count edits per file: first touch is create-or-modify, repeats are edits.
    prior = seen_paths.get(key, 0)
    seen_paths[key] = prior + _edit_weight(event)
    if prior == 0:
        # First time we see this path. Write is a create; Edit/MultiEdit on a
        # path we've never written usually means an existing file got modified.
        file_op = FileOp.CREATED if event.tool_name == "Write" else FileOp.MODIFIED
    else:
        file_op = FileOp.MODIFIED
    actions.append(Action(
        category=Category.FILES,
        target=path,
        raw=f"{event.tool_name} {path}",
        event_index=event.index,
        reversibility=Reversibility.REVERSIBLE,  # classify.py refines
        severity=Severity.INFO,
        succeeded=event.succeeded(),
        file_op=file_op,
        edit_count=seen_paths[key],
        path_escape=_path_escapes(path, session.cwd),
    ))


def _edit_weight(event: Event) -> int:
    """How many discrete edits a single tool call represents — a MultiEdit
    bundles several, so it should bump the per-file edit count by that many."""
    if event.tool_name == "MultiEdit":
        edits = event.tool_input.get("edits")
        if isinstance(edits, list) and edits:
            return len(edits)
    return 1


# --- network tools -------------------------------------------------------

def _net_tool_action(event: Event) -> Action:
    url = str(event.tool_input.get("url", "")) or str(event.tool_input.get("query", ""))
    target = url or event.tool_name
    return Action(
        category=Category.NETWORK,
        target=target,
        raw=f"{event.tool_name} {target}".strip(),
        event_index=event.index,
        reversibility=Reversibility.REVERSIBLE,
        severity=Severity.INFO,
        succeeded=event.succeeded(),
        detail="outbound fetch",
    )


# --- secret reads --------------------------------------------------------

def _maybe_secret_read(event: Event) -> Action | None:
    path = event.file_path
    if path and _SECRET_NAME_RE.search(path):
        return Action(
            category=Category.SECRETS,
            target=path,
            raw=f"Read {path}",
            event_index=event.index,
            reversibility=Reversibility.REVERSIBLE,
            severity=Severity.INFO,
            succeeded=event.succeeded(),
            detail="read secret-bearing file (exposure)",
        )
    return None


# --- shell commands ------------------------------------------------------

def _extract_shell(event, session, actions, seen_paths) -> None:
    command = event.command
    if not command:
        return
    ok = event.succeeded()
    for segment in _split_pipeline(command):
        toks = _tokens(segment)
        if not toks:
            continue
        # A leading `sudo` (with its own flags like `-E`) is a privilege
        # prefix, not the real verb — peel it off so `sudo pip install`
        # classifies as a pkg install. The privilege itself is still captured:
        # the segment text starts with "sudo", which the global-flag check sees.
        if toks and toks[0].lower() == "sudo":
            toks = toks[1:]
            while toks and toks[0].startswith("-"):
                toks = toks[1:]
        if not toks:
            continue
        verb = toks[0]

        # Order matters: most-specific / most-dangerous first so a `git push`
        # never falls through to a generic bucket.
        if _GIT_RE.match(verb):
            actions.append(_git_action(segment, toks, event, ok))
        elif _GH_RE.match(verb):
            act = _gh_action(segment, toks, event, ok)
            if act is not None:
                actions.append(act)
        elif _RM_RE.match(verb) or _PS_REMOVE_RE.match(verb):
            actions.append(_delete_action(segment, toks, event, session, ok, seen_paths))
        elif _MV_RE.match(verb) or _PS_MOVE_RE.match(verb):
            actions.append(_move_action(segment, toks, event, session, ok))
        elif _CHMOD_RE.match(verb):
            actions.append(_system_action(segment, event, ok,
                                           Severity.MEDIUM, "permission/ownership change"))
        elif _KILL_RE.match(verb):
            actions.append(_system_action(segment, event, ok,
                                           Severity.MEDIUM, "process kill"))
        elif _DOCKER_RE.match(verb):
            actions.append(_docker_action(segment, toks, event, ok))
        elif _SYSTEMCTL_RE.match(verb):
            actions.append(_system_action(segment, event, ok,
                                           Severity.MEDIUM, "service/daemon control"))
        elif _CRON_RE.search(segment):
            actions.append(_system_action(segment, event, ok,
                                           Severity.MEDIUM, "scheduled task / cron"))
        elif _DB_CLI_RE.search(segment) or _DB_DESTRUCTIVE_RE.search(segment) \
                or _MIGRATE_RE.search(segment):
            actions.append(_db_action(segment, event, ok))
        elif _CURL_RE.search(segment):
            actions.append(_curl_action(segment, event, ok))
        elif _PKG_RE.match(verb) and _is_install(toks):
            actions.append(_pkg_action(segment, toks, event, ok))
        else:
            # A read of a secret file via shell (cat .env) is still exposure.
            if verb in _READ_CMDS and _SECRET_NAME_RE.search(segment):
                actions.append(Action(
                    category=Category.SECRETS,
                    target=segment,
                    raw=segment,
                    event_index=event.index,
                    reversibility=Reversibility.REVERSIBLE,
                    severity=Severity.INFO,
                    succeeded=ok,
                    detail="shell read of secret file (exposure)",
                ))


def _git_action(segment: str, toks: list[str], event: Event, ok: bool) -> Action:
    sub = toks[1].lower() if len(toks) > 1 else ""
    rest = " ".join(toks[1:]).lower()
    detail = f"git {sub}"
    rev = Reversibility.REVERSIBLE
    sev = Severity.LOW

    force = ("--force" in rest or "-f" in toks[2:] or "--force-with-lease" in rest
             or "+" in rest)
    if sub == "push":
        if force:
            detail = "force-push (rewrites remote history — unrecoverable for others)"
            rev, sev = Reversibility.IRREVERSIBLE, Severity.CRITICAL
        else:
            detail = "push to remote (public once pushed)"
            rev, sev = Reversibility.IRREVERSIBLE, Severity.HIGH
    elif sub == "commit":
        detail = "local commit (amendable / resettable)"
        rev, sev = Reversibility.REVERSIBLE, Severity.LOW
    elif sub == "reset" and "--hard" in rest:
        detail = "reset --hard (discards working-tree changes)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    elif sub == "checkout" and ("--" in toks or "." in toks):
        detail = "checkout -- (discards local file changes)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    elif sub == "clean":
        detail = "clean (deletes untracked files)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    elif sub == "rebase":
        detail = "rebase (rewrites local history)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    elif sub in ("branch", "tag"):
        if "-d" in rest or "-D" in toks or "--delete" in rest:
            detail = f"{sub} delete"
            rev, sev = Reversibility.HARD_TO_REVERSE, Severity.LOW
        else:
            detail = f"{sub} create"
            rev, sev = Reversibility.REVERSIBLE, Severity.INFO

    return Action(
        category=Category.VCS,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=rev,
        severity=sev,
        succeeded=ok,
        detail=detail,
    )


def _gh_action(segment: str, toks: list[str], event: Event, ok: bool) -> Action | None:
    rest = [t.lower() for t in toks[1:]]
    sub = rest[0] if rest else ""
    is_write = sub in _GH_WRITE_SUBS and (
        sub == "api" and any(m in segment for m in ("-X POST", "-X PUT", "-X PATCH",
                                                    "-X DELETE", "--method"))
        or any(v in rest for v in _GH_WRITE_VERBS)
    )
    if not is_write:
        return None  # gh pr view / gh repo list etc. are read-only — skip
    return Action(
        category=Category.NETWORK,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=Reversibility.IRREVERSIBLE,
        severity=Severity.HIGH,
        succeeded=ok,
        detail="GitHub write via gh (PR/issue/repo mutation — visible to others)",
    )


def _delete_action(segment, toks, event, session, ok, seen_paths) -> Action:
    flags = [t.lower() for t in toks if t.startswith("-")]
    recursive = any(f in _RECURSIVE_FLAGS for f in flags) or any(
        "r" in f.lstrip("-") for f in flags if f.lstrip("-").isalpha())
    # Operand = last non-flag token (the path being deleted).
    operands = [_strip_quotes(t) for t in toks[1:] if not t.startswith("-")]
    target_path = operands[-1] if operands else segment
    escape = any(_path_escapes(op, session.cwd) for op in operands)
    if recursive:
        sev = Severity.HIGH
        detail = "recursive delete (rm -rf / Remove-Item -Recurse)"
    else:
        sev = Severity.MEDIUM
        detail = "file deletion"
    if escape:
        sev = Severity.HIGH
        detail += " — path outside cwd"
    return Action(
        category=Category.SYSTEM,
        target=target_path,
        raw=segment,
        event_index=event.index,
        reversibility=Reversibility.HARD_TO_REVERSE,
        severity=sev,
        succeeded=ok,
        file_op=FileOp.DELETED,
        path_escape=escape,
        detail=detail,
    )


def _move_action(segment, toks, event, session, ok) -> Action:
    operands = [_strip_quotes(t) for t in toks[1:] if not t.startswith("-")]
    escape = any(_path_escapes(op, session.cwd) for op in operands)
    return Action(
        category=Category.FILES,
        target=operands[-1] if operands else segment,
        raw=segment,
        event_index=event.index,
        reversibility=Reversibility.HARD_TO_REVERSE,
        severity=Severity.LOW,
        succeeded=ok,
        file_op=FileOp.MOVED,
        path_escape=escape,
        detail="move/rename",
    )


def _curl_action(segment, event, ok) -> Action:
    posting = bool(_POST_RE.search(segment))
    if posting:
        detail = "outbound HTTP with request body (data egress)"
        rev, sev = Reversibility.IRREVERSIBLE, Severity.HIGH
    else:
        detail = "outbound HTTP fetch"
        rev, sev = Reversibility.REVERSIBLE, Severity.LOW
    return Action(
        category=Category.NETWORK,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=rev,
        severity=sev,
        succeeded=ok,
        detail=detail,
    )


def _is_install(toks: list[str]) -> bool:
    lowered = [t.lower() for t in toks[1:]]
    return any(w in lowered for w in _PKG_INSTALL_WORDS)


def _pkg_action(segment, toks, event, ok) -> Action:
    is_global = any(f in segment.lower().split() for f in _GLOBAL_FLAGS) \
        or segment.lower().startswith("sudo")
    if is_global:
        detail = "global/system package install (affects machine-wide env)"
        sev = Severity.MEDIUM
    else:
        detail = "package install (mutates project/venv environment)"
        sev = Severity.LOW
    return Action(
        category=Category.PACKAGES,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=Reversibility.HARD_TO_REVERSE,
        severity=sev,
        succeeded=ok,
        detail=detail,
    )


def _db_action(segment, event, ok) -> Action:
    destructive = bool(_DB_DESTRUCTIVE_RE.search(segment))
    migration = bool(_MIGRATE_RE.search(segment))
    if destructive:
        detail = "destructive SQL (DROP/DELETE/TRUNCATE/UPDATE — data loss)"
        rev, sev = Reversibility.IRREVERSIBLE, Severity.CRITICAL
    elif migration:
        detail = "database migration (schema change applied)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.HIGH
    else:
        detail = "database CLI invocation"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    return Action(
        category=Category.SYSTEM,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=rev,
        severity=sev,
        succeeded=ok,
        detail=detail,
    )


def _docker_action(segment, toks, event, ok) -> Action:
    sub = toks[1].lower() if len(toks) > 1 else ""
    if sub in ("rm", "rmi", "system", "volume") and ("prune" in segment or sub in ("rm", "rmi")):
        detail = "docker remove/prune (containers/images/volumes gone)"
        rev, sev = Reversibility.HARD_TO_REVERSE, Severity.MEDIUM
    elif sub == "run":
        detail = "docker run (spawns container)"
        rev, sev = Reversibility.REVERSIBLE, Severity.LOW
    else:
        detail = f"docker {sub}"
        rev, sev = Reversibility.REVERSIBLE, Severity.INFO
    return Action(
        category=Category.SYSTEM,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=rev,
        severity=sev,
        succeeded=ok,
        detail=detail,
    )


def _system_action(segment, event, ok, severity, detail) -> Action:
    return Action(
        category=Category.SYSTEM,
        target=segment,
        raw=segment,
        event_index=event.index,
        reversibility=Reversibility.HARD_TO_REVERSE,
        severity=severity,
        succeeded=ok,
        detail=detail,
    )
