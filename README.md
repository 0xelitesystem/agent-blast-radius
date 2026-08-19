# agent-blast-radius

> Your agent finished. **What did it actually touch, and what can't you take back?**

`blast-radius` reads an AI coding agent's session transcript *after the fact* and reconstructs every side effect it had: the files it created, modified, and deleted; the commits it pushed; the data it sent over the network; the packages it installed; the destructive shell it ran. Then it answers the one question that matters when something went wrong: **which of those actions are irreversible, and did they actually succeed?**

It's a forensic report, not a live monitor. There's nothing to install ahead of time, no daemon, no wrapper around your shell. You point it at the transcript you already have, the JSONL Claude Code wrote to `~/.claude/projects/`, and it tells you the blast radius.

Zero dependencies. Pure Python stdlib. Works offline, no API keys, nothing leaves your machine.

## The problem

Agents now run unattended and act fast. You hand one a task, step away, and come back to a finished session and a vague worry: *what did it do while I wasn't looking?* Scrolling a thousand-line transcript to find the one `git push --force` or the one `curl --data @secrets.json` is exactly the kind of needle-in-a-haystack review nobody does carefully at 11pm during an incident.

Existing tooling is built for *before*: sandboxes, permission prompts, allow-lists, live audit logs you have to set up in advance. None of that helps when the thing already happened and all you have is the transcript. **agent-blast-radius is retroactive**, it reconstructs the damage from the record you already kept, the same way an incident responder reads logs after the breach.

The distinction that drives the whole report: **reversibility**. An edit is `ctrl-Z`. A local commit is `git reset`. But a push to a shared remote, a force-push that rewrites history, a `DELETE FROM`, data egressed to a webhook, those are gone. The report leads with that set and nothing else.

## What it catches

That's a real report of [`examples/demo-session.jsonl`](examples/demo-session.jsonl), an agent that edited three files, installed a package, committed, **force-pushed to origin**, recursively deleted `build/`, and **POSTed data to a webhook**:

```
  agent-blast-radius, what did this agent touch, and what's irreversible?
  session demo-session  -  10 events  -  /home/dev/acme-api

  BLAST TIER  CRITICAL
  3 files  -  2 vcs  -  1 network  -  1 packages  -  1 system

  IRREVERSIBLE & SUCCEEDED  (2)
  ● CRIT git push --force origin main
    └─ force-push (rewrites remote history, unrecoverable for others)  [event 6]
  ● HIGH curl -X POST https://hooks.acme.dev/deploy --data '{"status":"deployed"}'
    └─ outbound HTTP with request body (data egress)  [event 8]

  FILES  (3)
  ✓ INFO [created] /home/dev/acme-api/src/ratelimit.py  reversible
  ✓ INFO [modified] /home/dev/acme-api/src/app.py  reversible
  ✓ INFO [modified] /home/dev/acme-api/requirements.txt  reversible

  VERSION CONTROL  (2)
  ✓ LOW  git commit -am 'Add rate limiting'  reversible
  ✓ CRIT git push --force origin main  IRREVERSIBLE

  NETWORK / EXTERNAL  (1)
  ✓ HIGH curl -X POST https://hooks.acme.dev/deploy --data '{"status":"deploye...  IRREVERSIBLE

  PACKAGES / ENV  (1)
  ✓ LOW  pip install redis  hard-to-reverse

  SYSTEM / DESTRUCTIVE  (1)
  ✓ HIGH [deleted] build/  hard-to-reverse
```

Run it yourself:

```bash
blast-radius report examples/demo-session.jsonl
```

## Install

```bash
pip install git+https://github.com/0xelitesystem/agent-blast-radius
```

Python ≥ 3.10. No dependencies.

## Usage

```bash
# Reconstruct your most recent Claude Code session
blast-radius report latest

# A specific session by id prefix, or any transcript path
blast-radius report 8dcbd9b2
blast-radius report ~/.claude/projects/<project>/<session>.jsonl

# List recent sessions across all projects
blast-radius list

# Machine-readable output / Markdown report
blast-radius report latest --json
blast-radius report latest --md report.md

# Focus on one surface, or hide the noise
blast-radius report latest --only vcs
blast-radius report latest --danger-min high

# CI / automation gate: exit 1 if anything irreversible AND critical landed
blast-radius report latest --fail-on-critical
```

## What it tracks

Every side-effecting action the agent took is grouped into one of six surfaces:

| Surface | Examples |
|---|---|
| **Files** | `Write`/`Edit`/`MultiEdit`/`NotebookEdit`, plus shell `rm`/`del`/`Remove-Item`/`mv`, created vs. modified vs. deleted, with an edit count per file |
| **Version control** | `git commit` (reversible), `git push` (**irreversible**), `reset --hard` / `checkout --` / `clean` (destructive), `rebase`, force-push (**critical**), branch/tag create & delete |
| **Network / external** | `WebFetch`/`WebSearch`, `curl`/`wget`/`Invoke-WebRequest`, commands that POST data out (egress), `gh` API writes (PRs, issues, repos) |
| **Packages / env** | `pip`/`npm`/`yarn`/`cargo`/`apt`/`brew`/`uv` install, global/`sudo` installs rated higher than project-local |
| **System / destructive** | `rm -rf`, recursive deletes, `chmod`/`chown`, process kills, writes **outside the cwd** (path-escape), `sudo`, DB writes (`psql -c`, `DROP`, `DELETE FROM`, migrations), `docker run`/`rm`, `systemctl`, cron/scheduled tasks |
| **Secrets surface** | commands that read secret-bearing files (`cat .env`, reading `~/.aws/credentials`), flagged as **exposure** |

## How the verdict works

Each action gets two independent axes, and the session rolls up to one tier.

**Reversibility**, the core forensic axis:

| Level | Meaning |
|---|---|
| `reversible` | `ctrl-Z` territory, an edit, a local commit |
| `hard-to-reverse` | recoverable with effort, `rm` a file, `reset --hard`, a package install |
| **`IRREVERSIBLE`** | gone, pushed to a remote, data egressed, force-pushed, `DELETE FROM` |

**Severity**, danger, independent of reversibility (a noisy `curl` GET is reversible but still notable):

| Level | Typical action |
|---|---|
| INFO | a file write inside the cwd |
| LOW | a local commit, a project-local install |
| MEDIUM | `reset --hard`, a single-file delete, a global install, a `chmod` |
| HIGH | a `git push`, a recursive delete, data egress, a `gh` PR/issue write |
| CRITICAL | a force-push, destructive SQL that landed |

**Blast tier** is computed from the worst *successful* action: `CONTAINED` (only reversible edits) -> `MODERATE` (something hard-to-reverse landed) -> `WIDE` (an irreversible action landed) -> `CRITICAL` (an irreversible action that was also CRITICAL severity).

### Success-gating: a failed `rm` deleted nothing

The single most important rule: **an action that did not succeed had no side effect.** The tool matches every tool call to its result by id and reads the exit code. An `rm important.py` that exited non-zero is still shown, but downgraded to reversible/LOW with a `(failed, no effect)` note, and it can never raise the blast tier. A force-push that the remote rejected does not make a session CRITICAL. The report is about what *happened*, not what was *attempted*.

## Part of a suite

agent-blast-radius is one of three tools that read the same Claude Code transcript from different angles:

- **[agent-receipts](https://github.com/0xelitesystem/agent-receipts)**, did the agent's *claims* ("all tests pass") match what it did?
- **agent-blast-radius** (this one), what did it *touch*, and what's irreversible?
- **agent-leaks**, what *secrets* did it read or surface? (The secrets-exposure rows here are the seam; agent-leaks goes deep on that surface.)

They share a parser and a mental model, so the same `latest` transcript answers all three questions.

## Honest limitations

- **Transcript-only.** It reconstructs from what the transcript recorded. If a side effect happened inside a script the agent ran (`./deploy.sh` that pushes), the tool sees `./deploy.sh`, not the push inside it. It reads the commands the agent issued directly, not the full process tree.
- **Heuristic classification.** Reversibility and severity come from pattern-matching command shapes, not from executing or simulating anything. It errs toward flagging; an unusual command phrasing can be mis-bucketed or missed. Every row points at its exact event index so you can verify against the transcript yourself.
- **Success is inferred from exit codes and output.** A command that exits 0 but silently no-ops is counted as succeeded. A partially-applied destructive command is counted as fully applied.
- **Path-escape is lexical.** It compares the written path against the session cwd as text (so it works on transcripts captured on another machine), it does not resolve symlinks.

## Part of the agent accountability suite

- [agent-receipts](https://github.com/0xelitesystem/agent-receipts), did the agent's claims ("tests pass") match reality?
- [agent-leaks](https://github.com/0xelitesystem/agent-leaks), did it leak secrets into the transcript?
- **agent-blast-radius**, what irreversible actions did it take?
- [agent-rules](https://github.com/0xelitesystem/agent-rules), did it follow your `CLAUDE.md`?
- [agent-cost](https://github.com/0xelitesystem/agent-cost), where did the tokens and money go?

## Roadmap

- [ ] Adapters for other agents that persist transcripts (Codex CLI, OpenCode, Gemini CLI)
- [ ] Suite integration: one command that runs agent-receipts + agent-blast-radius + agent-leaks over `latest` and prints a combined incident card
- [ ] `blast-radius diff <a> <b>`, what changed in the blast radius between two runs of the same task
- [ ] Claude Code Stop-hook integration: auto-report every session, alert on CRITICAL
- [ ] Resolve `./script.sh` invocations against the repo to recover side effects inside scripts

## Development

```bash
git clone https://github.com/0xelitesystem/agent-blast-radius
cd agent-blast-radius
pip install -e .[dev]
pytest
python examples/make_demo.py && blast-radius report examples/demo-session.jsonl
```

## More

Part of a catalog of single-file browser tools and plain-language references, all MIT licensed and dependency-free: [0xelitesystem.github.io](https://0xelitesystem.github.io/). Built by [elitesystem.ai](https://elitesystem.ai).

## License

[MIT](LICENSE)
