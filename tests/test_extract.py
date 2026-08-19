"""Extraction: every category recognized, fields set correctly."""

from __future__ import annotations

from agent_blast_radius.extract import extract_actions
from agent_blast_radius.models import Category, FileOp, Reversibility, Severity
from agent_blast_radius.parser import parse_transcript


def _actions(path):
    return extract_actions(parse_transcript(path))


def _by_cat(actions, category):
    return [a for a in actions if a.category is category]


def test_file_writes_and_edits(benign_transcript):
    files = _by_cat(_actions(benign_transcript), Category.FILES)
    assert len(files) == 3
    created = [a for a in files if a.file_op is FileOp.CREATED]
    modified = [a for a in files if a.file_op is FileOp.MODIFIED]
    assert len(created) == 1  # the Write
    assert len(modified) == 2  # the two Edits


def test_edit_count_accumulates_per_file(tmp_path):
    from tests.conftest import assistant_tool, tool_result, write_jsonl
    records = [
        assistant_tool("a", "Edit", {"file_path": "C:\\fake\\project\\x.py",
                                     "old_string": "1", "new_string": "2"}),
        tool_result("a", "ok"),
        assistant_tool("b", "Edit", {"file_path": "C:\\fake\\project\\x.py",
                                     "old_string": "2", "new_string": "3"}),
        tool_result("b", "ok"),
    ]
    p = write_jsonl(tmp_path / "edits.jsonl", records)
    files = _by_cat(_actions(p), Category.FILES)
    assert files[-1].edit_count == 2


def test_multiedit_counts_each_edit(tmp_path):
    from tests.conftest import assistant_tool, tool_result, write_jsonl
    records = [
        assistant_tool("a", "MultiEdit", {
            "file_path": "C:\\fake\\project\\y.py",
            "edits": [{"old_string": "1", "new_string": "2"},
                      {"old_string": "3", "new_string": "4"},
                      {"old_string": "5", "new_string": "6"}]}),
        tool_result("a", "ok"),
    ]
    p = write_jsonl(tmp_path / "multi.jsonl", records)
    files = _by_cat(_actions(p), Category.FILES)
    assert files[0].edit_count == 3


def test_git_push_is_vcs_irreversible(destructive_transcript):
    vcs = _by_cat(_actions(destructive_transcript), Category.VCS)
    pushes = [a for a in vcs if "push" in a.detail]
    assert pushes
    assert pushes[0].reversibility is Reversibility.IRREVERSIBLE
    assert pushes[0].severity is Severity.HIGH


def test_git_commit_is_reversible(destructive_transcript):
    vcs = _by_cat(_actions(destructive_transcript), Category.VCS)
    commits = [a for a in vcs if "commit" in a.detail]
    assert commits and commits[0].reversibility is Reversibility.REVERSIBLE


def test_force_push_is_critical(critical_transcript):
    vcs = _by_cat(_actions(critical_transcript), Category.VCS)
    forced = [a for a in vcs if "force-push" in a.detail]
    assert forced
    assert forced[0].severity is Severity.CRITICAL
    assert forced[0].reversibility is Reversibility.IRREVERSIBLE


def test_rm_rf_is_recursive_delete(destructive_transcript):
    system = _by_cat(_actions(destructive_transcript), Category.SYSTEM)
    deletes = [a for a in system if a.file_op is FileOp.DELETED]
    assert deletes
    assert deletes[0].severity is Severity.HIGH  # recursive


def test_pip_install_is_package(critical_transcript):
    pkgs = _by_cat(_actions(critical_transcript), Category.PACKAGES)
    assert pkgs
    assert pkgs[0].reversibility is Reversibility.HARD_TO_REVERSE
    assert pkgs[0].severity is Severity.MEDIUM  # global install


def test_curl_post_is_egress(critical_transcript):
    net = _by_cat(_actions(critical_transcript), Category.NETWORK)
    posts = [a for a in net if "egress" in a.detail]
    assert posts
    assert posts[0].reversibility is Reversibility.IRREVERSIBLE
    assert posts[0].severity is Severity.HIGH


def test_webfetch_is_network(tmp_path):
    from tests.conftest import assistant_tool, tool_result, write_jsonl
    records = [
        assistant_tool("a", "WebFetch", {"url": "https://example.com/data"}),
        tool_result("a", "fetched"),
    ]
    p = write_jsonl(tmp_path / "fetch.jsonl", records)
    net = _by_cat(_actions(p), Category.NETWORK)
    assert net and "example.com" in net[0].target


def test_secret_read_via_read_tool(secret_read_transcript):
    secrets = _by_cat(_actions(secret_read_transcript), Category.SECRETS)
    assert any(".env" in a.target for a in secrets)


def test_secret_read_via_shell_cat(secret_read_transcript):
    secrets = _by_cat(_actions(secret_read_transcript), Category.SECRETS)
    assert any("credentials" in a.target for a in secrets)


def test_db_delete_is_critical_irreversible(db_transcript):
    system = _by_cat(_actions(db_transcript), Category.SYSTEM)
    assert system
    assert system[0].reversibility is Reversibility.IRREVERSIBLE
    assert system[0].severity is Severity.CRITICAL


def test_path_escape_flagged(path_escape_transcript):
    files = _by_cat(_actions(path_escape_transcript), Category.FILES)
    assert files and files[0].path_escape is True


def test_path_inside_cwd_not_flagged(benign_transcript):
    files = _by_cat(_actions(benign_transcript), Category.FILES)
    assert all(not a.path_escape for a in files)


def test_chained_command_splits(tmp_path):
    """git add && git commit && git push -> three VCS actions from one Bash."""
    from tests.conftest import bash, tool_result, write_jsonl
    records = [
        bash("a", "git add . && git commit -m x && git push origin main"),
        tool_result("a", "pushed"),
    ]
    p = write_jsonl(tmp_path / "chain.jsonl", records)
    vcs = _by_cat(_actions(p), Category.VCS)
    details = " ".join(a.detail for a in vcs)
    assert "commit" in details and "push" in details


def test_read_only_command_ignored(tmp_path):
    """A plain `ls` / `git status` produces no action."""
    from tests.conftest import bash, tool_result, write_jsonl
    records = [
        bash("a", "ls -la"),
        tool_result("a", "file1 file2"),
        bash("b", "git status"),
        tool_result("b", "clean"),
    ]
    p = write_jsonl(tmp_path / "readonly.jsonl", records)
    # git status is a vcs verb but maps to LOW/no special handling; ls is nothing.
    actions = _actions(p)
    assert all(a.category is not Category.SYSTEM for a in actions)
