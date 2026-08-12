---
name: security-forge
description: Run one cycle of the agentic security / bug-bounty pipeline against a target repo — comprehension (idea, entry points, roles, authn/authz) into a durable model, grep/SAST guardrail, dedicated authorization analysis, agentic data-flow analysis, Docker verification with debug instrumentation, reconciliation (new vs known vs mitigated), and notify-only local delivery (console + notifications.log). Use when the user runs /security-forge, points you at opt/workflow.md, asks to scan/analyze a repo, or when invoked headlessly on a schedule / from CI.
---

# security-forge — shortcut to the security-forge workflow

This skill is a thin entry point. **The canonical, self-contained instructions
live in [`opt/workflow.md`](../../../opt/workflow.md)** — read that file now and
follow it exactly, start to finish. It does not require this skill or any custom
agent to be installed; it works out of the box from the folder's files.

**Where the tool lives (installed vs. cloned).** All the scripts and docs this
skill uses sit in the security-forge folder. When this runs as an **installed
plugin** that folder is **`${CLAUDE_PLUGIN_ROOT}`**; when you run from a **clone**
of the repo it's the repo root (your current folder). Resolve it once and use it
for every command and bundled-file path:
```bash
SECFORGE_HOME="${CLAUDE_PLUGIN_ROOT:-$PWD}"
```
Read `opt/workflow.md` from `$SECFORGE_HOME/opt/workflow.md` and run helper scripts
as `python "$SECFORGE_HOME/scripts/pipeline.py" …`. State (the model, findings,
advisories, PoCs, `notifications.log`) is written under `$SECFORGE_HOME/knowledge/`.

**Target repo** (the one input): use the repo URL the user gave with the command
(e.g. `/security-forge https://github.com/owner/repo`), else `SECFORGE_TARGET_REPO`, else
`config.yaml → target.repo`. If a PR ref / branch / sha was mentioned, pass it as
the focus for incremental mode.

Then execute `opt/workflow.md`:
1. Preflight — bind `SECFORGE_TARGET_REPO`, `prep`, pick BASELINE vs INCREMENTAL.
2. Comprehension → durable model in `knowledge/<target>/` (idea, entry points,
   roles, authn/authz).
3. Grep guardrail (`sast/signatures.md`) → ranked hotspots.
4. Authorization analysis (`docs/AUTHZ_METHODOLOGY.md`).
5. Agentic data-flow analysis.
6. Verify **every** recorded finding live in Docker with `[SECFORGE]` debug
   instrumentation — not just a top-N slice (see §7).
7. Reconcile (new vs. known-unfixed vs. mitigated) and report **notify-only**
   locally (console + `notifications.log`) — never block or raise a PR check.
8. Draft a GHSA-style advisory per verified finding into the per-target
   `knowledge/<target>/advisories/` folder (one file per finding — see §8.5).
9. Ship a runnable PoC bundle per verified finding to
   `knowledge/<target>/poc/<slug>/` — `docker-compose.yml` + auto-showcase
   `poc.py` + `README.md` manual, reproducible with two commands (§8.6).
10. Tear down the Docker sandbox (`nuke`) and print a summary.

Run **one full cycle, non-interactively, then stop.** Do not loop. Honour every
guardrail in `opt/workflow.md` (notify-only, no questions, budgets, idempotency,
always nuke).
