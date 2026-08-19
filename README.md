# security-forge

Agentic security and bug-bounty pipeline for Claude Code.

Give Claude Code a repo. It maps the project, looks for vulnerabilities, and runs
the app to check that the ones it flags are actually exploitable. Results are
written to disk. It never touches the target's PRs or CI.

## Quickstart

Open Claude Code in this folder and run:

```
/security-forge https://github.com/OWNER/REPO
```

It clones the repo, runs the analysis, and writes findings to disk. Setup and the
rest of the options are in [docs/WORKFLOW.md](docs/WORKFLOW.md).

## Where the results end up

Results are saved under `knowledge/<target>/`, e.g.
`knowledge/github.com/OWNER/REPO/`:

| Path | What's in it |
|---|---|
| `notifications.log` | A readable log of every bug found. |
| `advisories/` | A write-up per confirmed bug: what it is, how bad, and the fix. |
| `poc/<bug>/` | A working exploit per confirmed bug. `cd` in, run `docker compose up -d`, then `python poc.py`. |
| `findings.json` | The raw list, used to avoid reporting the same bug twice. |

The same output prints to the Claude Code console during the run.

## What a run does

```
specify repo ─► clone ─► model exists for this target?
                            │
              no ───────────┴─────────── yes
         BASELINE (full)             INCREMENTAL (diff only)
              │                            │
              └──────► phased flow ◄───────┘
   A. Comprehension → durable model   (idea · entry points · roles · authn/authz)
   B. Grep guardrail                  (sast/signatures.md → ranked hotspots)
   C. Authorization analysis          (IDOR/BOLA, priv-esc, missing authn, …)
   D. Agentic data-flow analysis      (source → sink, real reachability)
   E. Verify in a container           (instrument the path, prove the sink fires)
   F. Reconcile                       (new vs. known-unfixed vs. mitigated)
   G. Notify-only (local report)      (never blocks or raises a PR)
```

Only CRITICAL and HIGH bugs are kept. After the first scan it runs against the
diff instead of the whole repo, and it tracks what was already reported, so
repeat runs surface only new bugs and one-time "fixed" notices.

## One folder, many repos

One copy of this folder can track many targets. State is separated per repo via
`SECFORGE_TARGET_REPO`. Run `python scripts/pipeline.py paths` to see where a
target lands on disk.

## Scan a whole org

There's an orchestrator that runs the workflow across every repo in a GitHub org
and stores the results in a committed SQLite DB (`db/security-forge.db`), so one
copy of security-forge becomes the durable memory of your whole org. It launches
one isolated, timeout-bounded Claude session per repo and is fully resumable.

```bash
python orchestrate.py --org my-org            # analyze every repo not done yet
python orchestrate.py --org my-org --rescan   # re-sync and re-analyze only the diffs
```

Put a `GITHUB_TOKEN` in `.env` for private repos. Details, flags, and how to query
the DB are in [docs/ORCHESTRATION.md](docs/ORCHESTRATION.md).
