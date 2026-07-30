"""Generate examples/demo-session.jsonl, a realistic WIDE/CRITICAL session.

The demo agent: edits 3 files, pip-installs a package, makes a local commit,
force-pushes to origin (irreversible + critical, rewrites shared history),
recursively deletes a directory, and curls data out to a webhook (egress).
Run it as:

    C:\\Python314\\python.exe examples\\make_demo.py

then point the tool at it:

    blast-radius report examples/demo-session.jsonl
"""

from __future__ import annotations

import json
from pathlib import Path

CWD = "/home/dev/acme-api"


def _assistant_text(text: str) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T15:30:00.000Z",
        "sessionId": "demo-blast-session",
        "cwd": CWD,
        "gitBranch": "main",
        "slug": "demo-session",
        "version": "2.0.0",
        "message": {"role": "assistant", "content": [{"type": "text", "text": text}]},
    }


def _tool(tool_id: str, name: str, tool_input: dict) -> dict:
    return {
        "type": "assistant",
        "timestamp": "2026-06-10T15:30:00.000Z",
        "sessionId": "demo-blast-session",
        "cwd": CWD,
        "gitBranch": "main",
        "slug": "demo-session",
        "version": "2.0.0",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}]},
    }


def _bash(tool_id: str, command: str) -> dict:
    return _tool(tool_id, "Bash", {"command": command})


def _result(tool_id: str, content: str, is_error: bool = False) -> dict:
    return {
        "type": "user",
        "timestamp": "2026-06-10T15:30:01.000Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": tool_id,
             "content": content, "is_error": is_error}]},
        "toolUseResult": (f"Error: Exit code 1\n{content}" if is_error
                          else {"stdout": content, "stderr": "", "interrupted": False}),
    }


def build() -> list[dict]:
    return [
        _assistant_text("I'll add rate limiting, install the dep, and ship it."),

        _tool("e1", "Write", {"file_path": f"{CWD}/src/ratelimit.py",
                              "content": "def limit():\n    ...\n"}),
        _result("e1", "File created successfully"),

        _tool("e2", "Edit", {"file_path": f"{CWD}/src/app.py",
                            "old_string": "app = Flask(__name__)",
                            "new_string": "app = Flask(__name__)\nlimit()"}),
        _result("e2", "ok"),

        _tool("e3", "Edit", {"file_path": f"{CWD}/requirements.txt",
                            "old_string": "flask", "new_string": "flask\nredis"}),
        _result("e3", "ok"),

        _bash("p1", "pip install redis"),
        _result("p1", "Successfully installed redis-5.0.1"),

        _bash("g1", "git commit -am 'Add rate limiting'"),
        _result("g1", "[main 9f2c1a0] Add rate limiting\n 3 files changed"),

        _bash("g2", "git push --force origin main"),
        _result("g2", "To github.com:acme/acme-api.git\n + 8a1...9f2  main -> main "
                      "(forced update)"),

        _bash("r1", "rm -rf build/"),
        _result("r1", ""),

        _bash("c1", "curl -X POST https://hooks.acme.dev/deploy "
                    "--data '{\"status\":\"deployed\"}'"),
        _result("c1", "{\"received\":true}"),

        _assistant_text("Rate limiting shipped, force-pushed to origin, "
                        "deploy webhook fired."),
    ]


def main() -> None:
    out = Path(__file__).resolve().parent / "demo-session.jsonl"
    out.write_text("\n".join(json.dumps(r) for r in build()) + "\n", encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
