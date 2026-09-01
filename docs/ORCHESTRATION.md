# Org orchestrator — scan a whole GitHub org, store it in the repo

The single-repo workflow (`opt/workflow.md`) analyzes one target. The orchestrator
runs that workflow across an entire org: it lists every repo, then launches one
dedicated, timeout-bounded Claude session per repo, and records every outcome in a
committed SQLite database. One copy of security-forge becomes the durable memory of
your whole org.

## Why a separate process drives it

A single Claude session is context-bounded: it analyzes a handful of repos, then
stops. `orchestrate.py` is a plain subprocess manager that holds no model context,
so it can drain hundreds of repos that no single session could. Each repo gets a
fresh session that sees only that one repo, so context exhaustion and cross-repo
bleed go away. If a session stalls, errors, or gets killed by a platform
safeguard, the orchestrator kills it at the deadline, tears down the sandbox,
records the result, and moves to the next repo. It never stops for one repo.

## The database (this is the "data in the repo")

`db/security-forge.db` (SQLite, stdlib only) is committed on purpose — it is the
org-wide store. Two tables:

- `targets` — one row per repo: clone URL, org, latest push, status, the commit it
  was last analyzed at, attempts, and severity counts. This is the queue and the
  ledger.
- `findings` — one row per MEDIUM/HIGH/CRITICAL finding, keyed by a stable id and
  tagged with the repo and commit. Mirrors each repo's `findings.json` into one
  place you can query across the whole org.

Only the `.db` is committed; its transient journal sidecars are gitignored. The
per-repo working data (`knowledge/`, `target/`, `state/`) stays local.

## Setup

Put a token in `.env` so the org listing can see private repos and dodge rate
limits (public orgs work without one):

```
GITHUB_TOKEN=ghp_...
```

## Run it

```bash
# just ONE repo (one bounded session, recorded in the DB), then stop
python orchestrate.py --repo https://github.com/owner/repo

# sync the org into the queue, then analyze every repo not yet done
python orchestrate.py --org my-org

# a user account instead of an org
python orchestrate.py --user my-handle

# re-sync and re-analyze only the repos that changed since last time (the diffs)
python orchestrate.py --org my-org --rescan

# see the plan without launching anything
python orchestrate.py --org my-org --dry-run
```

For a quick interactive scan of one repo you don't need the orchestrator at all —
just run the skill, `/security-forge https://github.com/owner/repo`, or the
workflow directly. `--repo` is the headless equivalent that also records the
result into the DB alongside your org runs.

## Local source folders (no clone URL needed)

Point security-forge straight at code already on disk — a checkout, a vendored
drop, a folder that never had a remote:

```bash
python orchestrate.py --path /home/me/projectX          # one local folder, one session
python orchestrate.py --path ./services/api             # relative paths work too
python orchestrate.py --repo file:///srv/code/app       # file:// URL is equivalent
```

A local target is keyed as **`local/<foldername>`** (so its model/findings live in
`knowledge/local/<foldername>/`). If the folder is a **git repo** it's cloned into
the throwaway `target/` with history, so incremental diffs work exactly like a
remote. If it's a **plain folder** (no `.git`) it's copied, and changed files are
detected by a file-signature manifest — so re-running still analyzes just what
changed. `config.yaml → target.repo` also accepts a path or `file://` URL.

The wrappers `drain.sh` / `drain.ps1` do the same and relaunch the orchestrator if
its own process dies, until the queue is empty. Extra flags pass straight through.

Useful flags: `--timeout <sec>` (hard per-repo limit, default 3600 = 1h; raise it
for verification-heavy targets, e.g. `--timeout 7200`), `--max-repos N`
(stop after N this run), `--max-attempts N` (skip a repo after N aborts),
`--model <name>`, `--include-forks`, `--include-archived`, `--output-dir <path>`
(send the db/logs/knowledge somewhere other than the repo folder), `--no-sync`.

## Which AI runs each session (backends)

The whole engine — scripts, Docker sandbox, the `verify-poc` advisory gate, the DB
— is provider-neutral; a **backend** just decides which agent CLI runs a session.
Default is **Claude Code**; you can point it at any other headless agentic CLI.

- **claude-code** (default) — `claude` runs the session (unchanged).
- **litellm** — NATIVE, no external CLI: security-forge runs its own tool-use loop
  (`scripts/litellm_agent.py`, tools `bash`/`read_file`/`write_file`) over **LiteLLM**,
  so any LiteLLM model works directly — `openai/gpt-5`, `gemini/gemini-2.5-pro`,
  `anthropic/claude-3-7-sonnet`, `ollama/llama3`, a local endpoint. Needs
  `pip install litellm`; keys come from the env / `--agent-env`.
- **cli-adapter** — wrap any headless agentic CLI from a command TEMPLATE with
  `{prompt}` and `{model}` placeholders (no shell; `{prompt}` stays one argument).
- **named presets** — define your agent "types" once in `config.yaml` under
  `agent.backends.<name>` (examples ship for `codex`, `gemini`, `aider`) and select
  one by name.

```bash
# native LiteLLM (no external CLI) — model is a LiteLLM string:
python orchestrate.py --org OWNER --backend litellm --model openai/gpt-5 \
  --agent-env OPENAI_API_KEY=sk-...
python orchestrate.py --org OWNER --backend litellm --model ollama/llama3   # local, no key

# pick a preset "type" + a model:
python orchestrate.py --org OWNER --backend codex  --model gpt-5
python orchestrate.py --org OWNER --backend gemini --model gemini-2.5-pro

# everything on the command line — no config.yaml, no .env needed.
# --agent-cmd alone implies cli-adapter; --agent-env sets provider keys/endpoints:
python orchestrate.py --repo <url> \
  --agent-cmd "aider --model {model} --yes --message {prompt}" \
  --agent-output text --model gpt-5 \
  --agent-env OPENAI_API_KEY=sk-... --agent-env OPENAI_BASE_URL=https://my-proxy/v1
```

Everything a backend needs is specifiable inline: `--agent-cmd` (the command, with
`{prompt}`/`{model}`), `--agent-output` (`text`|`jsonl`), `--model`, and repeatable
`--agent-env KEY=VALUE` (provider keys, base URLs — merged into the child's
environment, never printed). Precedence is CLI flag > `config.yaml agent:` >
default; an explicit `--agent-cmd` implies `--backend cli-adapter`. `--model` is
normalized for `claude-code` (`opus4.8` → `claude-opus-4-8`) and passed **verbatim**
to every other backend. Provider keys can also come from the environment or
security-forge's `.env` (the orchestrator loads it and passes it to the child) —
`--agent-env` just lets you skip both. Two notes: weaker models produce more false positives — the
`verify-poc` gate is what keeps that honest; and parallel subagents are a Claude
Code feature, so other CLIs fall back to inline role execution (less parallel, same
method).

## Sweep vs rescan

- **Default (sweep):** analyzes repos that were never analyzed, plus any left in
  `error`. Already-analyzed repos are left alone.
- **`--rescan`:** re-syncs the org, then re-queues any analyzed repo whose upstream
  `pushed_at` changed since we analyzed it. The per-repo session clones the new
  commit, diffs against the last analyzed commit, and analyzes just the changes.
  Note: `--rescan` **re-lists the whole org** of every repo it tracks, so it also
  discovers and queues repos you never analyzed. If you only want to refresh YOUR
  repos, use `--known-only`.
- **`--known-only`:** re-check ONLY the repos you've already analyzed (that have a
  model in `knowledge/`) — your repos, **not their whole orgs**. Skips all org
  discovery/sync; each session pulls latest and analyzes just the diff. This is the
  right "sync the latest for my repos" mode, especially right after a `backfill`
  (which restores your analyzed repos but, under `--rescan`, would re-list their
  full orgs — e.g. 18 repos across apache/elastic/grafana can balloon to thousands).

Diff detection is exact: the push marker is snapshotted at analysis time and
compared for inequality, so there are no false re-queues from timestamp formatting.

## Resumability

Everything is in the DB, so any run continues from what's left. A repo left
mid-flight by a crash or a kill is reaped on the next run: it goes back to `error`
for a retry, or to `skipped` after `--max-attempts` aborts so one bad repo can't
wedge the queue.

**Partial-result salvage.** A session that is killed at the deadline (or crashes)
before it can run `org.py record` does not lose the findings it already wrote —
those live in `knowledge/<slug>/findings.json`, which teardown preserves. After
every incomplete session the orchestrator runs `org.py record --partial`, folding
whatever was found into the DB (with severity counts) without marking the repo
analyzed, so it stays retryable. The per-repo session is also told its wall-clock
budget and is instructed to checkpoint findings as it goes, work breadth-first on
large repos, and reserve time to record + nuke before the deadline — so a timeout
yields a clean partial cycle instead of a total loss.

## Query what you've collected

```bash
python scripts/orgdb.py summary                      # counts by status + severity
python scripts/orgdb.py targets --status analyzed    # the ledger
python scripts/orgdb.py findings --min-sev HIGH      # every HIGH/CRITICAL, all repos
python scripts/orgdb.py show --slug github.com/org/repo
```

Add a repo by hand (outside an org) with
`python scripts/orgdb.py add --repo https://github.com/owner/repo`.
