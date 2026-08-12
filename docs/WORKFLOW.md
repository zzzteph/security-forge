# security-forge — how to run it

**One entry point, everywhere.** Point Claude Code at [`opt/workflow.md`](../opt/workflow.md)
and give it a repo URL. The same file drives interactive, headless, and CI runs.
Running **locally is the default**; GitHub Actions is optional.

---

## Runs anywhere (with prerequisites)

security-forge is a portable folder of Markdown + a little Python. It runs on **Linux,
macOS, Windows, and ARM boards (Raspberry Pi 4, arm64)** — anywhere the
prerequisites exist:

| Prerequisite | Why | Notes |
|---|---|---|
| `git` | clone/update the target on the console | **your** responsibility to install & have repo access |
| `claude` (Claude Code CLI) | the console that runs the workflow | interactive or `claude -p` |
| Python 3.11+ (3.13 tested) + `PyYAML` | mechanical glue in `scripts/` | `pip install -r requirements.txt` |
| `ripgrep` (`rg`) | the grep guardrail | pure signal, no Docker |
| Docker + Compose (or Podman) | verification sandbox (Phase E) | optional — see below; podman is used automatically when docker is absent (`SECFORGE_CONTAINER_CLI` forces one) |

**Without a container runtime** (no Docker or Podman — e.g. a minimal Pi):
comprehension, the grep guardrail, the authorization pass, and data-flow analysis
all still run. Only Phase E's dynamic verification is skipped — findings are then
reported as unverified candidates.

**On arm64 (Raspberry Pi):** the one caveat is **dynamic verification**: the
*target app* must build/run on arm64 too — many do, but an x86-only image won't.
If it can't run, security-forge keeps the finding as an unverified candidate
rather than failing.

Nothing in the core path is OS-specific: `scripts/*.py` are cross-platform;
`run_cycle.sh` covers Linux/macOS/Pi, `run_cycle.ps1` covers Windows.

---

## Local (default)

**Interactive** — from a `claude` session in this folder (or the VS Code extension):
```
Follow opt/workflow.md for https://github.com/OWNER/REPO
```
Add *"…PR #123"* or *"…ref <branch/sha>"* to focus on a change. `/security-forge` is a
shortcut for the same thing.

**Headless — one cycle:**
```bash
./run_cycle.sh https://github.com/OWNER/REPO           # Linux / macOS / Pi
```
```powershell
$env:SECFORGE_TARGET_REPO="https://github.com/OWNER/REPO"; .\run_cycle.ps1   # Windows
```

**Scheduled** — cron the shell runner (Pi/Linux) or Task Scheduler the PowerShell
one. Each run re-pulls and does incremental analysis.

### What a run produces
- `knowledge/<target>/` — the durable model (`PROJECT/ENTRYPOINTS/ROLES/AUTH.md`,
  `model.json`) + `findings.json`. **This is what makes the next run incremental.**
  Locally it simply persists on disk between runs; back it up if you like (it's
  yours — security-forge never auto-commits it).
- Local report (stdout + `knowledge/<target>/notifications.log`) — **only new
  findings and one-time "mitigated" notices**. Known-but-unfixed issues are never
  re-emitted.

---

## GitHub Actions (optional)

Not required. If you want CI, [.github/workflows/analyze.yml](../.github/workflows/analyze.yml)
runs the same `opt/workflow.md` headless and — because it runs in **this** repo,
not as a check inside the target's PR — **can never block or raise anything on
that PR**. It reports locally (to the run log + `notifications.log`), exactly like
a local run.

**Set up:**
- Secrets on the security-forge repo: `ANTHROPIC_API_KEY`.
- Optional vars: `SECFORGE_DEFAULT_REPO` (for the `schedule` trigger),
  `SECFORGE_MODEL` (e.g. `opus`).
- Private target? Add your own git-auth step — cloning creds are your
  responsibility, same as locally.

**Trigger it** three ways:
1. **Manually** — Actions → *security-forge-analyze* → Run, enter the repo (+ optional PR ref).
2. **Scheduled** — the built-in `cron` sweeps `SECFORGE_DEFAULT_REPO`.
3. **Per-PR (real-time)** — drop this tiny hook in the **target** repo so each PR
   pings security-forge (this is the only change a target ever needs, and it's optional).
   It POSTs a `repository_dispatch` to your own security-forge repo with plain curl
   (no third-party action):
   ```yaml
   # target repo: .github/workflows/security-forge.yml
   name: security-forge
   on: { pull_request: { types: [opened, synchronize, reopened] } }
   jobs:
     dispatch:
       runs-on: ubuntu-latest
       steps:
         - run: |
             curl -sf -X POST \
               -H "Authorization: token ${{ secrets.SECFORGE_DISPATCH_PAT }}" \
               -H "Accept: application/vnd.github+json" \
               https://api.github.com/repos/OWNER/security-forge/dispatches \
               -d '{"event_type":"security-forge-pr","client_payload":{"repo":"https://github.com/${{ github.repository }}","ref":"${{ github.event.pull_request.head.sha }}","pr":"${{ github.event.pull_request.number }}"}}'
   ```
   It only *notifies* security-forge; it sets no status and gates nothing, so the PR is
   never blocked.

**Persistence across runners.** CI runners are ephemeral, so the durable model is
kept on a lean branch **`model/<slug>`** of the security-forge repo, restored before and
pushed after each run by `scripts/model_branch.sh` — committed by the CI bot
(`github-actions[bot]`), **never** to the target repo. Locally you don't need
this; the `knowledge/` folder on disk is the persistence.

---

## Tuning
`config.yaml` controls focus areas, budgets (`max_analyzer_agents`,
`max_verify_per_cycle`), the report policy, and the verification sandbox. The
always-on grep guardrail is [`sast/signatures.md`](../sast/signatures.md).
