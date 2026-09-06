# security-forge UI — continuous scanning control plane

A web app on top of the security-forge engine: add repositories, give each a cron
schedule, and let it scan continuously. Findings persist in one global table;
anything not rediscovered on a later scan is marked **mitigated** with the reason.
Every finding is presented in the advisory format and exports to **PDF**, plus a
per-repo and global **executive report**. Static analysis only (no verification),
no notifications, everything in the DB.

## Run it

```bash
cd webapp
OPENAI_API_KEY=sk-... docker compose up --build
# open http://localhost:8000   — login  root / root  (you must change it on first login)
```

Or build/run by hand (from the repo root):

```bash
docker build -f webapp/Dockerfile -t security-forge-ui .
docker run --rm -p 8000:8000 -v "$PWD/sf-data:/data" -e OPENAI_API_KEY=sk-... security-forge-ui
```

Published to GHCR on every push: `ghcr.io/zzzteph/security-forge-ui:latest`
(multi-arch amd64 + arm64).

## What you can do

- **Auth** — login page, default `root`/`root`, forced password change, change it
  anytime under Settings.
- **Repositories** — add a repo with: git URL, **cron schedule** (e.g. `0 3 * * *`),
  **backend** (litellm / claude-code / codex / gemini / aider), **model**, extra
  orchestrator args, and **context** (focus areas, "this is not an issue", triage
  hints — injected into the scan).
- **Continuous scanning** — the scheduler fires each repo on its cron; scans run one
  at a time. "Scan now" for an ad-hoc run. Every scan dumps its full log.
- **Findings** — one global table across all repos, filter by status/severity. On a
  re-scan, a finding that's gone → **mitigated**, with the reason saved.
- **Advisories & reports** — each finding renders as a GHSA-style advisory,
  downloadable as **PDF**; per-repo and global **executive report** PDF.
- **Backends** — a page shows which backends/tools are installed and configurable;
  set defaults under Settings.

## How it maps to the engine

| UI action | Under the hood |
|---|---|
| Run a scan | `orchestrate.py --repo <url> --backend … --model … --silent` (no `--verify`) |
| Per-repo context | injected via `SECFORGE_EXTRA_CONTEXT` into the scan prompt |
| Findings | read from `knowledge/<slug>/findings.json`, reconciled into the global table |
| Data | `SECFORGE_DATA_DIR=/data` → `db/`, `knowledge/`, `logs/` all under the mounted volume |

## Provider keys

Pass the key(s) for your chosen backend as env vars: `OPENAI_API_KEY`,
`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, or `SECFORGE_LLM_API_KEY` (generic, for a
custom endpoint). `GITHUB_TOKEN` for private repos. Set `SECFORGE_UI_SECRET` to keep
login sessions valid across restarts.

## Notes

- **No verification** here by design (the UI runs without a nested Docker daemon), so
  findings are static candidates rendered as advisories — use the CLI `--verify` flow
  when you want reproduced PoCs.
- Backend quality still matters; a stronger model yields fewer false positives.
