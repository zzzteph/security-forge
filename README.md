# security-forge

Agentic security and bug-bounty pipeline for Claude Code.

Give Claude Code a repo. It maps the project, looks for vulnerabilities, and runs
the app to check that the ones it flags are actually exploitable. Results are
written to disk. It never touches the target's PRs or CI.

## How to run

Open Claude Code in this folder and scan one repo:

```
/security-forge https://github.com/OWNER/REPO
```

Or from the terminal:

```bash
python orchestrate.py --repo https://github.com/OWNER/REPO   # one repo
python orchestrate.py --org OWNER                            # every repo in an org
python orchestrate.py --org OWNER --rescan                   # re-scan only what changed
```

First run needs a one-time [setup](docs/WORKFLOW.md). For org scans, put a
`GITHUB_TOKEN` in `.env`. Results land under `knowledge/<repo>/`, and org runs also
record into `db/security-forge.db`.

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

`orchestrate.py --org` runs the workflow across every repo in a GitHub org, one
isolated and timeout-bounded session at a time, and stores everything in a
committed SQLite DB (`db/security-forge.db`) so one copy of security-forge becomes
the durable memory of your whole org. It's fully resumable, and `--rescan`
re-analyzes only the repos that changed. Full flags and DB queries are in
[docs/ORCHESTRATION.md](docs/ORCHESTRATION.md).

## Examples

```bash
# --- Targets --------------------------------------------------------------
python orchestrate.py --repo https://github.com/OWNER/REPO   # one remote repo
python orchestrate.py --org OWNER                            # a whole GitHub org
python orchestrate.py --path /home/me/projectX              # a LOCAL folder (git or not)
python orchestrate.py --path ./services/api                 # relative path works too

# --- Re-checking your own repos (no org discovery) ------------------------
python orchestrate.py --known-only                          # re-check ONLY repos you've analyzed
python orchestrate.py --rescan --org OWNER                  # re-list an org + analyze what changed

# --- Choosing the AI backend ----------------------------------------------
python orchestrate.py --org OWNER --model opus4.8           # Claude Code (default)
python orchestrate.py --org OWNER --backend litellm --model openai/gpt-5 \
  --agent-env OPENAI_API_KEY=sk-...                         # native LiteLLM (no external CLI)
python orchestrate.py --path ./app --backend litellm --model ollama/llama3 \
  --agent-base-url http://localhost:11434                   # fully local model, offline
python orchestrate.py --org OWNER --backend codex --model gpt-5   # wrap the Codex CLI (preset)
python orchestrate.py --repo <url> \
  --agent-cmd "aider --model {model} --yes --message {prompt}" --model gpt-5   # any CLI, inline

# --- Where results go -----------------------------------------------------
python orchestrate.py --org OWNER --output-dir /data/sf \
  --reports-dir /data/security-reports                     # flat, cross-project reports/ folder

# Browse everything found, across all projects, in one place:
cat /data/security-reports/INDEX.txt
```

Every finding across every project is also collected into one flat, plain-text
folder — `reports/<date>_<project>_<severity>_<issue>.txt` plus a greppable
`INDEX.txt` — so you can review vulnerabilities regardless of which repo they came
from. Advisories and a runnable PoC are written only for findings whose exploit
actually reproduced.

## Run it in Docker

Published to GHCR on every push (multi-arch: amd64 + arm64/Raspberry Pi):

```bash
docker pull ghcr.io/zzzteph/security-forge:latest
```

security-forge runs its own verification sandbox, so give the container a Docker
daemon (mount the host socket) and, on Linux, host networking so the sandbox's
port-binding and probes line up:

```bash
# analyze a local folder with Claude Code
docker run --rm -it \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/sf-data:/data" \
  -e ANTHROPIC_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest --path /data/mysrc --model opus4.8

# or a whole org with the native LiteLLM backend (no Claude CLI needed)
docker run --rm -it \
  --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/sf-data:/data" \
  -e OPENAI_API_KEY=sk-... \
  ghcr.io/zzzteph/security-forge:latest \
  --org OWNER --backend litellm --model openai/gpt-5
```

Put source to analyze under `./sf-data` (mounted at `/data`) and everything —
`db/`, `knowledge/`, and the central `reports/` — persists there. There's also a
`docker-compose.yml` for convenience, and you can build locally with
`docker build -t security-forge .` (add `--build-arg INSTALL_CLAUDE=false` for a
lean, LiteLLM-only image). Full details in [docs/DOCKER.md](docs/DOCKER.md).
