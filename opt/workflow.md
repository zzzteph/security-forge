# security-forge — security analysis workflow (self-contained brain)

**You point Claude Code at this file and give it a repo URL; it does the rest.**
This document is the single source of truth for one analysis run. It works
**out of the box** — it does not require any Claude skill or custom agent to be
installed. Everything it needs is in this folder: helper scripts in `scripts/`,
the grep guardrail in `sast/signatures.md`, the authorization catalog in
`docs/AUTHZ_METHODOLOGY.md`, and role briefs in `.claude/agents/*.md` (read as
plain files when not registered as agents).

> **How to run it**
> - Interactive (Claude console or VS Code extension), from this folder:
>   *"Follow `opt/workflow.md` for `https://github.com/OWNER/REPO`"* (optionally
>   *"…PR #123"* or *"…ref `<branch/sha>`"*).
> - Headless / CI: `claude -p "Follow opt/workflow.md for <repo-url>"
>   --dangerously-skip-permissions`.
> - The optional `/security-forge` skill is just a shortcut that says exactly the above.

---

## 0. Inputs & the single entry point
The only required input is the **target repo URL**, taken from (in order): the
user's message → `SECFORGE_TARGET_REPO` env → `target.repo` in `config.yaml`.
Optional: a **PR ref / branch / sha** to focus on.

**First action — locate the tool, then bind the target for every command below.**

1. **Resolve `SECFORGE_HOME`** — the security-forge folder that holds `scripts/`,
   `sast/`, `docs/`, and `.claude/agents/`. It is **`${CLAUDE_PLUGIN_ROOT}`** when
   this runs as an installed plugin, otherwise the **repo root** you're running
   from. **Every `scripts/...`, `sast/...`, `docs/...`, and `.claude/agents/...`
   path in this document is relative to `$SECFORGE_HOME`** — prefix them with it
   (or `cd "$SECFORGE_HOME"` at the start of each shell session).
2. **Bind the target** — derive the URL and pass it via `SECFORGE_TARGET_REPO` on
   *every* script call so all state is keyed per-target (one folder tracks many
   repos). The Bash tool's env does not persist between calls, so set both inline
   each call:
```bash
SECFORGE_HOME="${CLAUDE_PLUGIN_ROOT:-$PWD}"
SECFORGE_TARGET_REPO="<url>" python "$SECFORGE_HOME/scripts/pipeline.py" paths
```
(PowerShell: `$H = if ($env:CLAUDE_PLUGIN_ROOT) { $env:CLAUDE_PLUGIN_ROOT } else { $PWD };`
`$env:SECFORGE_TARGET_REPO="<url>"; python "$H\scripts\pipeline.py" paths`.) Run
`paths` first and note `knowledge_dir` — that is where the durable model + findings
for this target live (all under `$SECFORGE_HOME`, so state persists with the tool).

**Machine-agnostic note:** invoke the helper scripts with whichever Python exists
on the host — **`python3`** on Linux / macOS / Raspberry Pi (arm64), `python` on
Windows. For brevity the examples below write `python scripts/...`; run them as
`python "$SECFORGE_HOME/scripts/..."` (or after `cd "$SECFORGE_HOME"`) and
substitute `python3` where that's the launcher. Nothing else is OS-specific.

## 1. Guardrails (read before doing anything)
- **Notify-only. Never block, fail, or "raise" a PR.** This workflow observes and
  reports locally (console output + a per-target `notifications.log`). It must never
  post a failing check, commit status, or PR comment. In CI, exit 0 no matter what.
- **Report bar: MEDIUM, HIGH and CRITICAL — and nothing below.** LOW,
  informational, theoretical, and best-practice/hardening issues are **never**
  recorded or reported.
- **The confirmation standard is IDENTICAL at every severity — this is what keeps
  the channel free of noise.** Lowering the floor to MEDIUM must NOT lower the
  evidence requirement; MEDIUM is a statement about *exploitation preconditions*,
  never about *confidence*. Every finding at every severity must satisfy all six:
  1. **Confirmed in code you actually read** — not a grep/pattern match, not
     inferred from a function or annotation name.
  2. **Traced** — `entrypoint → … → sink` (or the exact missing check), with a
     `file:line` per hop. **Cannot trace it to the sink ⇒ it is not a finding**
     (report it as `untraced` for a human, never as a finding).
  3. **User-reachable** from a `model.json` entry point.
  4. **Concrete impact** — one sentence on what the attacker actually obtains.
     "Could be dangerous" is not an impact.
  5. **A false-positive filter was checked and named** (`sast/signatures.md` →
     *False-positive filters*). Never dismiss or keep silently.
  6. **Severity derived, not asserted** — via the procedures in
     `docs/AUTHZ_METHODOLOGY.md`. Where evidence is missing, take the **lower**
     rating. Never round up to make something look important.
- **What MEDIUM is, and is not.** MEDIUM = a **confirmed, reachable, real defect
  whose exploitation carries a genuine precondition** — e.g. a real missing
  ownership check on a UUID-keyed object with no disclosure path found (needs an
  already-known id); a flaw needing victim interaction, a non-default config, or
  affecting only low-sensitivity data. MEDIUM is **not** a home for: unconfirmed or
  untraced candidates, unreachable code, defense-in-depth nits, missing security
  headers, a bare MD5 with no security role, verbose errors, missing rate limits
  away from the auth mechanism, or anything you would have to argue for. Those are
  **dropped**. If you are tempted to file something as MEDIUM because it is "not
  quite nothing", that is exactly the thing to drop.
- **When value or confidence is doubtful, drop it.** Quality over quantity:
  **zero findings is a fine, honest result** — a single false positive costs more
  credibility than ten true findings earn.
- **User-reachable only.** Analyze and report only code reachable by a user —
  on a call path from a `model.json` entry point. Dead code, tests, fixtures,
  migrations, build/admin tooling that no entry point reaches is out of scope.
- **Never ask questions — ever.** In any mode (interactive, headless, or CI), do
  not stop to ask the user anything. If something is ambiguous, make the most
  reasonable choice, log it, and keep going. Never wait for input.
- **Stay in scope.** Touch only this folder and the Docker sandbox. Never modify
  the target's real remote. Never push the throwaway clone. Never exfiltrate
  anything — reporting is local only.
- **Budgets** (`config.yaml → analysis`): cap parallel fan-out per phase at
  `max_recon_agents` (recon), `max_authz_agents` (authz area + auth-mechanism),
  and `max_analyzer_agents` (dataflow). **`max_verify_per_cycle` no longer caps
  verification — verify EVERY recorded finding on a live environment (see §7).**
  The budgets order the work (highest severity / most reachable first); keep
  verifying until every finding has a terminal verdict (`verified` / `triaged` /
  `dismissed` / an explicit unverified-with-blocker), across multiple passes if
  needed.
- **Hard deadline & large-repo strategy.** When run headlessly by the
  orchestrator, the whole cycle has a hard wall-clock budget (`orchestrate.py
  --timeout`, default 1h) after which the session is killed and anything not
  written to the store is lost. So: **(1) checkpoint findings the moment they
  clear the bar** — `add-finding` immediately, `set-status` right after
  verifying; never batch to the end. **(2) On a large codebase, don't attempt
  exhaustive coverage in one cycle** — respect the fan-out caps above, analyze the
  highest-value areas first, record partial coverage (note what's unmapped in
  `coverage.unmapped`), and let the next incremental cycle continue from the
  persisted `knowledge/` model. **(3) Land the plane** — reserve the last few
  minutes to run `org.py record` + `verify.py nuke`; if time is short, stop
  hunting, record what you have, then record + nuke. A clean partial cycle beats a
  killed one.
- **Verify all findings dynamically.** Do not leave any recorded finding (MEDIUM
  included) as a static-only candidate when the target can be built: stand it up in
  the Docker sandbox and prove (or refute) each one at runtime with `[SECFORGE]`
  evidence. Verification is the strongest false-positive filter you have — prefer
  spending the cycle on it over adding another analysis area.
- **Draft an advisory per verified finding** (see §8.5) — one GHSA-style file per
  finding, collected in the per-target `advisories/` folder.
- **Ship a runnable PoC bundle per verified finding** (see §8.6) — a self-contained
  folder with a `docker-compose.yml` that boots the vulnerable target and a
  `poc.py` that auto-showcases the exploit, so a person can reproduce it manually
  with two commands (`docker compose up -d` → `python poc.py`). Save the exact
  build/seed assets the verifier already used — do NOT leave them in scratch/temp.
- **Idempotency.** The findings store dedupes and tracks what was reported. Only
  **new** vulns and **one-time mitigations** are sent (see §7). Never re-report a
  known, still-open finding.
- **Always tear down** the Docker sandbox at the end (§10), even on error.
- **Time-box.** If the target won't build/run after reasonable effort, record
  candidates as unverified and move on.
- **Show progress.** Keep the user in the loop (see below): a status line per
  phase to stdout, also appended to the per-target `notifications.log` if
  `report.progress`.

### Progress (keep the user in the loop)
Emit a short status at **each phase boundary** — to stdout always (so the console
/ VS Code / CI logs show live progress), and appended to the per-target
`notifications.log` (tagged `progress`) when `config.yaml → report.progress` is
set, so there is a durable record of the run (only real findings and the final
summary are emitted as loud notices):
```bash
python scripts/pipeline.py notify --silent "⏳ <repo>@<sha>: comprehension done — 42 entrypoints, 3 roles; running authz…"
```
Announce: **start** · **comprehension** (entrypoints/roles) · **guardrail**
(hotspots) · **authz** (candidates) · **dataflow** (candidates) · **verifying**
(n) · **done** (the §10 summary — emitted as a notice, not silent). If running
interactively, also keep a short `TodoWrite` plan updated.

### How to run the analysis roles (works with or without installed agents)
Each analysis role has a **brief** at `$SECFORGE_HOME/.claude/agents/<role>.md`. To
run a role, spawn a subagent with the Agent tool:
- **Preferred:** `subagent_type: "<role>"` (recon-cartographer / authz-analyzer /
  code-analyzer / finding-verifier) if that type is available (it will be when
  Claude runs from this folder or the installed plugin).
- **Always-works fallback:** `subagent_type: "general-purpose"`, and begin the
  prompt with *"Read `$SECFORGE_HOME/.claude/agents/<role>.md` (substitute the
  absolute path) and follow it exactly as your instructions,"* then add the
  assignment. The brief is a normal file, so this needs nothing installed.
- **Last resort** (no Agent tool at all): do the role's work inline yourself
  following the same brief.
Run independent subagents in parallel (one message, multiple Agent calls).

## 2. Preflight — clone/update & pick the mode
Cloning is a plain `git clone` run on the console (via `prep`). Ensuring **git is
installed and can access the target repo** (public, or your own credentials for a
private one) is the user's responsibility — security-forge does not manage git auth.
```bash
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py setup   # first time only (create dirs, load .env)
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py prep     # git clone/pull, diff, repo shape -> JSON
```
Read `prep`'s JSON: `commit`, `changed_files`, `is_first_scan`, `shape`. Then
decide the **mode** by checking whether a model already exists
(`knowledge_dir/model.json`):
- **BASELINE** — no `model.json` (or `is_first_scan`): build the full model and
  analyze the whole codebase.
- **INCREMENTAL** — `model.json` exists: load it, and focus on `changed_files`
  (+ what's reachable from them). If a PR ref was given, diff against the PR.

## 3. Phase A — Comprehension → the durable project model (steps 1–4)
Goal: produce/refresh `knowledge_dir/{PROJECT,ENTRYPOINTS,ROLES,AUTH,TRUST_BOUNDARIES}.md`
and a machine-readable `knowledge_dir/model.json`, so future runs don't re-derive
this. Follow the **recon-cartographer** brief.

- **BASELINE:** run the cartographer over the whole repo (scope `full`; for a
  large repo, split by subtree across parallel cartographers — up to
  `max_recon_agents` — and merge). It
  covers: **(1) the idea/purpose**, **(2) every entry point** (attack surface),
  **(3) roles/users**, **(4) authn + authz**.
- **INCREMENTAL:** only refresh the parts the diff touches. If `changed_files`
  include route/handler/middleware/auth/role files, re-map those entry points and
  the auth sections; otherwise reuse the existing model. Update
  `model.json.last_analyzed_commit`.

Write `model.json` yourself (deterministically) from the cartographer fragment(s)
so parallel agents never race on it. Minimum schema:
```json
{
  "target": "github.com/owner/repo", "repo_url": "...", "schema_version": 1,
  "built_commit": "<sha>", "last_analyzed_commit": "<sha>",
  "idea": "...", "stack": {"languages": [], "frameworks": [], "datastores": [], "boots_with": "", "ports": []},
  "crown_jewels": [],
  "entrypoints": [{"id": "GET /api/x/:id", "kind": "http", "method": "GET", "route": "/api/x/:id",
                   "handler_file": "", "handler_symbol": "", "line": 0, "params": [],
                   "auth_required": true, "roles": [], "object_lookup": "", "files": []}],
  "roles": [{"name": "", "represented_by": "", "can": [], "file": ""}],
  "auth": {"authn": {"mechanism": "", "established_at": "", "identity_read": ""},
           "authz": {"model": "", "enforced_at": [], "gaps": [], "object_level": ""}},
  "trust_boundaries": [], "coverage": {"areas": [], "unmapped": []}
}
```
`entrypoints[].id` and `.files` are what incremental runs use to map a changed
file back to an entry point.

## 4. Phase B — Grep guardrail (the "basic SAST" that points the agent) (step 5)
Run the signature sweep from `sast/signatures.md` with ripgrep over the analysis
scope (whole tree on baseline; `changed_files` + neighbours on incremental).
Pick the sink patterns for the languages in `shape`, e.g.:
```bash
rg -n --no-heading -e '<sink-pattern>' target/<slug>/ -g '*.py'
```
For each hit, grep nearby **source** patterns to rank source-reachable hits
first, then **drop every hit not reachable from a `model.json` entry point** —
only user-reachable sinks proceed. Also run the **authorization markers** section
against every entry point, and the **authn-soundness markers** section over the
auth/login/session/token/reset/MFA/OAuth code — that second sweep is what the
mandatory `auth-mechanism` agent (§5) starts from, and most of its signal is an
*absent* hardening call beside a present mechanism. **Output = a ranked hotspot
list of user-reachable candidates, not findings.** Hand it to the agents in §5–6.

**Apply the false-positive filters** (`sast/signatures.md` → *False-positive
filters*) while ranking: when a neutralizing step is present on the path
(parameterized query, allowlist, `basename()`, autoescape, `safe_load`, a
principal-scoped query…), drop the candidate and **name the filter you applied**.
This is where most noise is meant to die — before an agent spends a cycle on it.

## 4.5. Phase B2 — The repo-wide id-disclosure index (build ONCE, before authz)
Spawn **one** `authz-analyzer` with `area: "disclosure-index"`. It does not hunt
for missing checks; it maps, for every object type in the model, **every place an
id or sensitive datum is emitted and to which principal** — list/search/export
endpoints, ids echoed in response bodies, ids in server-rendered HTML or shipped
JS bundles, verbose errors, debug endpoints, JWT/cookie payloads, ids in URLs
(`Referer` leakage), email / reset / invite / referral links, public profiles,
autocomplete, OpenAPI & GraphQL schema examples, log lines, and correlation from
values the attacker already holds (email, order number, sequential sibling).

It writes `knowledge_dir/DISCLOSURE_INDEX.md` and returns a `disclosure_index`
array; merge that into `model.json` under `disclosure_index` and **pass it to every
authz agent in §5 and to the composition pass in §6.5**.

**Why this phase exists:** the leak that makes a UUID-keyed BOLA exploitable
almost always lives in a *different area* from the missing check. Without a global
index, each area agent honestly reports "no leak found", the finding is rated
MEDIUM, and the disclosure sits in the file next door. This phase is what makes
the exposure gate in §5 correct rather than merely local. On incremental runs,
refresh it only if `changed_files` touch serializers, list/export endpoints,
templates, error handling, or logging; otherwise reuse it.

## 5. Phase C — Access-control analysis (step 6)
This is the class the grep guardrail can only hint at. Follow the
**authz-analyzer** brief and `docs/AUTHZ_METHODOLOGY.md`. Spawn authz subagents
up to `max_authz_agents` (area agents + the one mandatory auth-mechanism agent;
on a large repo prefer fewer, higher-value routers this cycle over covering every
subtree at once), each given: the model (`ENTRYPOINTS.md` / `ROLES.md` /
`AUTH.md` / `model.json`), `DISCLOSURE_INDEX.md` from §4.5, the authz-marker
hotspots, and (incremental) the changed files. Two kinds of agent:

- **Area agents** (split by router/subtree) — walk checks **A–J** over every entry
  point: missing authn, vertical priv-esc, **IDOR/BOLA (object-level)**,
  inconsistent siblings, mass-assignment, tenant isolation, client-controlled
  identity, wrong-place checks, GraphQL/batch — each keeper carrying a
  **two-principal PoC**.
- **One mandatory `auth-mechanism` agent** — audits authentication **soundness**
  (checks **K–P**): session lifecycle, password-reset / verification tokens,
  JWT & signature verification, OAuth/OIDC flow, MFA & step-up, and
  anti-automation on auth endpoints. Always spawn this one, on baseline and
  whenever a diff touches auth, login, session, token, reset, MFA or OAuth code.
  It audits each *mechanism* once end to end (generator + verifier + storage, all
  cited) rather than route by route, and its PoC shape is the **single-attacker
  ATO test** (forge or brute-force the credential, then prove `/me` returns the
  victim). Every finding must state whether it yields ATO, of **whose** account,
  and what the attacker must know first.

  Rate K–P on what the attacker ends up holding: unauthenticated takeover of an
  **arbitrary** account (predictable reset token, `alg: none` / alg confusion,
  unverified signature, host-header reset poisoning, uncapped OTP brute force,
  `redirect_uri` code theft, MFA bypassable on a sibling endpoint) ⇒ CRITICAL;
  takeover needing a realistic precondition (victim's email, one victim click,
  a targeted account, non-default config) ⇒ HIGH; no-rotation with no demonstrated
  hijack path, missing idle timeout, enumeration alone, or a login rate-limit gap
  with no amplifier ⇒ **below the bar, drop it**. Rate-limit gaps count only
  **on the auth mechanism itself** and only where they enable brute force of a
  guessable secret — that is the difference between a CRITICAL and a nit.

For BOLA/IDOR the agents must **read the test files / fixtures / factories /
seeds / migrations** to learn the real **ID structure** and any seed creds, then
**derive** severity via the decision procedure in `docs/AUTHZ_METHODOLOGY.md →
Severity` (who can reach it → write-outranks-read → data sensitivity →
exposure). Exposure is the gate:
- sequential / short-numeric / natural-key ids ⇒ `enumerable: yes` ⇒ mass-harvest
  ⇒ CRITICAL/HIGH;
- **UUIDv4 / long random ⇒ `enumerable: no` — never treat a UUID as
  brute-forceable.** The agent then consults `DISCLOSURE_INDEX.md` and runs the
  **mandatory local leak hunt** for anything the index missed (list/search/export,
  response bodies, JS bundles, errors, JWT/cookie, URLs/`Referer`, emails/reset
  links, public profiles, OpenAPI, logs, correlation).
  - **Leak found (index or local) + cited `file:line` ⇒ rate as enumerable** ⇒
    HIGH/CRITICAL.
  - **No leak found after an honest hunt ⇒ MEDIUM** — still a real finding, still
    reported, but honestly labelled: the `poc` and `severity_rationale` must state
    that exploitation **requires an already-known or leaked id** and name where you
    looked. Never inflate it to HIGH.
  - **Provably unobtainable by any principal ⇒ not a finding**, drop it.
Where evidence is missing the agent takes the **lower** rating; nothing is rounded
up to clear the bar. Each finding carries `id_structure`, `enumerable`,
`disclosure` (the cited leak, or where you looked and found none), `trace`, and a
`severity_rationale` naming the rubric row.

Each authz agent also returns a **`coverage_matrix`** — one row per method+path
for every entrypoint it reviewed, SAFE rows included, each with a verdict
(`SAFE` / `VULNERABLE` / `UNVERIFIABLE` / `UNTRACED`). Merge these and check the
union against `model.json.entrypoints`: **any entrypoint with no row was never
reviewed** — assign it to another agent or record it in `coverage.unmapped`. Route
`unverifiable` (out-of-band enforcement) and `untraced` entries to the run summary
for human follow-up, not to `findings`. Also record standalone
**information-disclosure** endpoints.

## 6. Phase D — Agentic data-flow analysis (step 7)
Follow the **code-analyzer** brief. Fan out one subagent per hot area (from the
model's entry points, the hotspots, the focus list, and changed files), up to
`max_analyzer_agents`, in parallel. Each traces untrusted input → dangerous sink,
confirms/dismisses the grep candidates, and returns findings with an explicit
`entrypoint → sink` reachability argument, auth state, and an `instrument_hint`.
**A finding requires a concrete call path from a user entry point**; sinks not
reachable by a user are dropped, never reported.

**Record only keepers that clear the bar — MEDIUM/HIGH/CRITICAL that satisfy all
six points of the confirmation standard in §1** (dedupe against the store first
with `get --brief`):
```bash
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py add-finding --json '{
  "title":"...", "severity":"CRITICAL|HIGH|MEDIUM", "category":"...",
  "file":"...", "line":0, "cwe":["CWE-..."], "entrypoint":"...",
  "reachability":"entrypoint -> ... -> sink (auth state)", "poc":"...",
  "fp_filter_checked":"which false-positive filter you ruled out",
  "severity_rationale":"why this severity, per the derivation procedure" }'
```
Do **not** store LOW, informational, unconfirmed, untraced, unreachable, or
best-practice issues (a bare MD5 with no security role, missing headers, verbose
errors, a reachable sink with no real impact) — dismiss them with a reason.
**A MEDIUM must be as well-evidenced as a CRITICAL**; it differs only in the
precondition an attacker faces. Storing noise violates the report bar.

## 6.5. Phase D2 — Composition & re-rating (cheap, high-value, do not skip)
Findings arrive from agents that each saw one area. Before verification, do one
pass over the **merged** set plus `DISCLOSURE_INDEX.md` and ask what composes:

- **Disclosed id + BOLA** — re-run the exposure gate for every MEDIUM BOLA against
  the *complete* index and every `disclosures` entry any agent reported. A leak
  found in another agent's area promotes that MEDIUM to HIGH/CRITICAL. This is the
  main reason this phase exists.
- **Open redirect + OAuth `redirect_uri`** (code theft ⇒ ATO) and **open redirect
  + SSRF** (allowlist bypass) — a MEDIUM redirect on an allowed host becomes
  CRITICAL when it lands inside an auth flow or an allowlisted fetcher.
- **Info-disclosure + reset/MFA flow** — a leaked token, email, or user id that
  turns a HIGH authn finding into an unauthenticated CRITICAL.
- **Priv-esc + any authenticated-only finding** — if a role gate is bypassable,
  every finding rated "admin-only, therefore lower" must be re-rated at the
  privilege the attacker can actually reach.

Re-rating **may go down as well as up**: if the composition you assumed does not
hold, lower the severity and say so. Record the change in `severity_rationale`
(what composed, with `file:line`), and log a one-line note per re-rating. Then
`add-finding` any genuinely new composed finding, linking its constituents.

## 7. Phase E — Verify hypotheses in Docker with debug instrumentation
Only if `verify.enabled`. **Verify EVERY recorded finding on a live environment —
not just a top-N slice.** Take all findings that haven't reached a terminal
verdict (`new`/`triaged`/unverified), ordered highest-severity / most-reachable
first, and dynamically verify each. Reuse ONE shared sandbox across findings for
the same target when practical (build/boot once, then verify each finding against
it) so "verify all" stays affordable. Mark each `verifying`, then spawn a
**finding-verifier** subagent. It boots the target in the sandbox
(`scripts/verify.py …`). **Pre-pull any large public base image first** —
`python scripts/verify.py pull --image <ref>` (e.g. `kartoza/geoserver:2.26.0`) —
so the multi-minute fetch runs on its own long timeout instead of eating into
container-start (and the deadline); the image is cached for the rest of the run
(`nuke` never removes images). Then it **inserts `[SECFORGE]` debug log lines along the
source→sink path in the throwaway clone** (or enables the app's own query/SQL
logging as the equivalent evidence), rebuilds, fires the exploit (injection marker
/ `{{7*191}}` / loopback SSRF sentinel / two-principal IDOR), and reads
`docker logs` / the HTTP response to prove the tainted value reached the sink.
For any finding whose **runtime precondition is unmet** (plugin/feature not shipped
in the default build, dialect-specific, etc.), verify against a config that DOES
ship it where reasonable; if it is genuinely unreachable in a real deployment,
`triaged` it with the concrete reason rather than reporting it as live. Keep going
until **every** finding has a verdict — do not stop at `max_verify_per_cycle`.
**Persist the reproducible artifacts:** whatever the verifier built to prove a
`verified` finding (Dockerfile / `docker-compose.yml`, the seed/setup script, the
exploit `poc.py`) must be written into that finding's durable PoC folder
(`<knowledge_dir>/poc/<slug>/`, see §8.6) — never left in scratch/temp — so the
person can re-run it by hand later. Apply each verdict:
```bash
# present in source but not reachable in the running app:
python scripts/pipeline.py set-status <id> triaged  --note "not reachable in default deploy: <why>"
# false positive:
python scripts/pipeline.py set-status <id> dismissed --note "<why>"
# MEDIUM, reachable & confirmed at runtime (no PoC bundle by design — instrumented
# runtime evidence is the standard for MEDIUM):
python scripts/pipeline.py set-status <id> verified --evidence "<request+response/[SECFORGE] log excerpt>"
```

**HIGH/CRITICAL: `verified` is EARNED by the runnable bundle, not asserted.** The
instrumented `[SECFORGE]` run above is how you *find* the flow; it is NOT what
marks a HIGH/CRITICAL `verified`. For every HIGH/CRITICAL candidate, build the
self-contained PoC bundle now (§8.6) and run it end to end exactly as a human
would — then let that result set the status:
```bash
# builds nothing, mark the bundle location first so verify-poc can find it:
python scripts/pipeline.py set-status <id> --poc-dir "<knowledge_dir>/poc/<NN>-<slug>"
# THE GATE — boots the bundle (`docker compose up -d --build`), runs poc.py, and
# marks the finding `verified` (+ poc_verified) ONLY if it exits 0 AND prints
# `EXPLOITED ✓`. Any other outcome leaves it NOT verified and exits non-zero:
python scripts/pipeline.py verify-poc <id> --dir "<knowledge_dir>/poc/<NN>-<slug>"
```
Do **not** hand-set `verified` on a HIGH/CRITICAL — only `verify-poc` may, by
actually reproducing it. If `verify-poc` does not pass, the bundle is wrong or the
finding is a false positive: fix the bundle and re-run, or downgrade
(`triaged`/`dismissed`). A HIGH/CRITICAL that never reproduces via `verify-poc`
gets **no advisory** (§8.5) — this is exactly the "PoC that never succeeds but the
advisory exists anyway" failure, closed at the source.

If the target can't be built/run at all, keep findings as **unverified candidates**
(still reportable per policy, clearly marked unconfirmed) — but an unverified
finding is **never** `poc_verified`, so it gets no advisory.

**A failed verification is a signal, not a formality.** If the exploit does not
fire and you cannot show a concrete runtime precondition that explains why, the
static reasoning was probably wrong — prefer `dismissed` over reporting it as an
unconfirmed candidate. Unverified MEDIUMs are the likeliest noise in the whole
pipeline; hold them to that standard.

### Reconciliation (incremental only — new vs. known vs. mitigated)
Before reporting, reconcile against the diff so the notification channel stays
clean:
- **Still present, already reported** → stay silent.
- **Still present, not yet reported** → report as NEW (§8).
- **No longer present / no longer reproduces** → it was **mitigated**. For a
  previously-verified finding whose file (or any file on its traced path) changed,
  re-check it (static: the vulnerable code/pattern is gone; or dynamic: the
  verifier's re-check reports `mitigated`). Then:
  ```bash
  python scripts/pipeline.py set-status <id> fixed --evidence "mitigated: <what changed>"
  ```
  and send the one-time "mitigated" notice (§8), marking `--fix-reported`.
- **dismissed** → never report.

## 8. Phase F — Report locally (notify-only)
Policy (`config.yaml → report`): emit verified findings, flag unverified
candidates as unconfirmed, and emit one-time mitigation notices. Only
emit what isn't already reported:
```bash
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py get --unreported --min-sev MEDIUM --brief
```
Order the report **highest severity first** and state the severity on every line,
so a MEDIUM never reads with the urgency of a CRITICAL. For a MEDIUM, the
precondition belongs in the headline — e.g. *"requires a known invoice id (no
disclosure path found)"* — not buried in the detail.
Reports go to stdout and the per-target `notifications.log` (plain text). **Verified**:
```bash
python scripts/pipeline.py notify "$(cat <<'MSG'
🔴 VERIFIED — {severity}: {title}
Target: {repo} @ {short_commit}
Where: {file}:{line}  ({category}, {cwe})
Reachability: {entrypoint→sink, auth state}
Proof: {what confirmed it — [SECFORGE] log/response}
PoC: {payload/request}
MSG
)"
python scripts/pipeline.py set-status <id> --reported --note "reported locally"
```
**Unverified (any reported severity)** → same shape prefixed
`🟠 UNCONFIRMED — {severity}` with a `Status: awaiting/failed verification
({reason})` line, then `--reported`.
**Mitigated** → `✅ MITIGATED — {severity}: {title}` with what changed,
then `set-status <id> --fix-reported`.
If `report.attach_report_file`, also `notify --file reports/<id>.md` (records the path).

## 8.5. Phase F2 — Draft a GitHub Security Advisory (HIGH & CRITICAL only)
**Advisories are for HIGH and CRITICAL findings only — AND ONLY when the runnable
PoC bundle actually reproduced.** The hard gate: write an advisory for a finding
**iff `poc_verified` is true** — i.e. its bundle passed `pipeline.py verify-poc`
(exit 0 + `EXPLOITED ✓`) this cycle (§7). Confirm before writing:
```bash
python scripts/pipeline.py get --min-sev HIGH --brief   # only entries with "poc_verified": true get an advisory
```
**Never** write an advisory from a self-asserted `verified` status, from static
reasoning, or for a `triaged`/unverified/`could_not_run` finding — those get no
advisory, no exceptions. (A HIGH/CRITICAL you believe is real but could not
reproduce goes to the executive summary's limits section, not to an advisory.)
**Never draft an advisory for a
MEDIUM**, even a verified one — a coordinated-disclosure document for a flaw that
needs an already-known id devalues the ones that matter. MEDIUMs are reported in the
notification channel (§8) and summarised in the executive summary (§8.7); that is
their whole delivery path. Write the advisory as
a standalone markdown file and collect them **in a per-target `advisories/`
folder**:
```
<knowledge_dir>/advisories/GHSA-<NN>-<short-slug>.md      # one file per finding
```
(Number them `01`, `02`, … per target; slug from the finding, e.g.
`GHSA-02-workflowmanualtasks-get-idor.md`.) Create the folder if absent; write one
file per finding (idempotent — overwrite the same slug on re-runs, don't duplicate).
**Immediately link the file to its finding** so the janitor can tell a backed
advisory from an orphan:
```bash
python scripts/pipeline.py set-status <id> --advisory-path "<knowledge_dir>/advisories/GHSA-<NN>-<slug>.md"
```
Each file MUST contain, in this order:
1. **Header metadata** — project, ecosystem/package, **affected versions** (state
   what was confirmed vs. what needs range-checking), the exact **verified commit /
   version**, **severity**, **CWE(s)**, and a **CVSS v3.1 vector + score**.
2. **Summary** — one paragraph: what, who can exploit it, impact.
3. **Details** — root cause with exact `file:line` refs and the offending code;
   why the guard is missing/insufficient; reachability from a `model.json` entry
   point and the required privilege.
4. **PoC** — concrete, reproducible steps/requests from the live verification
   (the two-principal request+response or the `[SECFORGE]`/DB-log evidence).
5. **Impact** — vulnerability class, who is affected, what an attacker gains; note
   any honest caveat (dialect-gated, enumerability, non-default config).
6. **Remediation** — the concrete fix (the missing check / escape / scope filter).
Keep advisories factual and coordinated-disclosure-ready; **do not** file/publish
them anywhere (no PRs, no public posts) — they are drafts for the person to submit.
`triaged`/unreachable findings must say so in the header rather than read as live.

## 8.6. Phase F3 — Reproducible PoC bundle (the HIGH/CRITICAL verification gate)
Every HIGH/CRITICAL gets a **self-contained, runnable PoC folder** — and this
bundle is not a write-up produced *after* verification, it **is** the verification
(§7): the finding only becomes `verified` when `pipeline.py verify-poc` boots this
exact bundle and it reproduces (exit 0 + `EXPLOITED ✓`). So build it before you
call the finding verified, and make it pass — the artifact a human runs and the
artifact that gated the advisory are then one and the same, which is what stops a
"green advisory, red PoC" divergence. (A verified MEDIUM does not get a bundle; its
request/response evidence stays on the finding record and is cited in the
executive summary.)
```
<knowledge_dir>/poc/<NN>-<short-slug>/
├── docker-compose.yml     # boots the vulnerable target with ONE command
├── Dockerfile             # only if a build/overlay is needed (else omit)
├── setup.(sh|py|php)      # seed: create the two principals + preconditions (idempotent)
├── poc.py                 # AUTO-SHOWCASE: runs the exploit end-to-end, prints evidence + verdict
└── README.md              # the manual (below)
```
Requirements:
- **Two-command UX.** The README's happy path must be: (1) `docker compose -p <slug> up -d`
  (wait for ready), then (2) `python poc.py` — which authenticates, performs any
  seed if `setup.*` isn't auto-run, fires the exploit, prints the request/response
  or `[SECFORGE]`/DB-log evidence, and ends with a clear `EXPLOITED ✓` / `NOT
  VULNERABLE ✗` line and a non-zero exit on failure. Prefer host stdlib only (no
  pip installs) so it runs anywhere; pin the app version/commit in the compose.
- **Faithful & pinned.** Use the SAME image/build/dialect the verifier confirmed
  against (pin the tag/commit; note it in the README). If a non-default config is
  required (a dialect, an enabled plugin, a feature flag), bake it into the compose
  and state it.
- **Reuse, don't reinvent.** These are exactly the assets the finding-verifier
  produced in §7 — copy them here verbatim (compose, seed, `poc.py`) rather than
  authoring new ones; only add the `README.md` manual.
- **It must actually pass the gate.** After writing the bundle, run `python
  scripts/pipeline.py verify-poc <id> --dir <this folder>` and confirm it exits 0
  and flips the finding to `verified`/`poc_verified`. If it doesn't reproduce, the
  bundle (or the finding) is wrong — fix it and re-run, or downgrade the finding.
  `poc.py`'s success line must be exactly `EXPLOITED ✓` and it must exit non-zero
  on failure, because that string + exit code ARE the gate.
- **README.md** must contain: the finding title + severity + affected version/commit;
  **Prerequisites** (Docker); **Run** (the two commands + expected wait/URL/creds);
  **Expected output** (what a successful exploit prints, with a sample); **Manual
  steps** (the equivalent curl/requests to verify by hand without `poc.py`);
  **Teardown** (`docker compose -p <slug> down -v` [+ `docker rmi` if built]); and a
  one-line **Caveat** where relevant (dialect-gated / non-default / enumerability).
- Idempotent across re-runs (overwrite the same slug folder; don't duplicate).
- Do NOT auto-run these bundles as part of the pipeline's own teardown — they are
  for the person; the pipeline still `nuke`s its own sandbox in §10.

## 8.7. Phase F4 — Executive summary for the repo (one per target, refreshed)
Advisories are per-finding and written for a maintainer. The **executive summary**
is per-repo and written for someone who will not read the advisories: an owner,
a manager, an appsec lead deciding where to spend the next sprint. Write one file,
**overwritten in full every cycle** so it always reflects current reality:
```
<knowledge_dir>/EXECUTIVE_SUMMARY.md
```
It describes the **current state of the target**, not the events of this run.
Sections, in this order:

1. **Header** — target repo, commit analysed (short sha + date), whether this was a
   baseline or incremental cycle, and the scan coverage in one line
   (*"n of m entry points reviewed; k unmapped"* from the merged `coverage_matrix`).
2. **Verdict — one sentence a non-specialist can act on.** e.g. *"Two verified
   critical flaws allow any logged-in user to read every customer's invoices and to
   issue refunds; both are in the billing API and both are one-line fixes."* No
   jargon, no CVSS in this line.
3. **Risk posture table** — counts by severity × status (verified / unconfirmed /
   triaged / mitigated), plus the delta since the previous summary
   (*"+1 critical, −2 high (fixed)"*). Keep it small enough to read at a glance.
4. **What an attacker can do today** — the HIGH/CRITICAL findings as 3–6 bullets in
   **business** terms, ordered by severity, each naming the affected crown jewel
   from `model.json` and linking its advisory file. *"Read any customer's payment
   history (PII + financial) — GHSA-01"*, not *"CWE-639 in invoices.py:55"*.
   MEDIUMs are covered separately in section 6 — do not mix them in here, so this
   section stays the list of things that are exploitable right now.
5. **Systemic patterns, not just instances** — the more valuable half of this
   document. Where the same root cause recurs: *"object lookups are unscoped
   throughout the billing router — 4 of 7 endpoints; the codebase has an
   `assertOwner` helper that is simply not called"*, or *"authorization is enforced
   per-handler with no central layer, so every new endpoint is opt-in secure."*
   Name the missing control, not the individual bugs.
6. **Medium-severity findings** — a required section, because MEDIUMs get **no
   advisory and no PoC bundle**, so this document is the only place they are
   explained. List each: what it is, its `file:line`, and — the important part —
   **the precondition that keeps it a MEDIUM**, stated plainly: *"a real missing
   ownership check, but object ids are random UUIDs and we found no endpoint, log,
   email or bundle that leaks them — an attacker needs an id they already know."*
   Then say what would **promote** it (*"if any list/export endpoint starts
   returning these ids to non-owners, this becomes HIGH"*), so the reader can see
   which of their own changes would make it urgent. Group them if several share a
   root cause. Do not pad this section — it carries the same evidence bar as the
   rest; a MEDIUM here is a confirmed, traced defect, not a suspicion.
7. **What is solid** — controls confirmed working (SAFE rows, hardened parsers,
   parameterized data layer). This is what makes the document trustworthy rather
   than alarmist, and it tells the reader what not to re-litigate.
8. **Recommended order of work** — a short numbered list: the fixes, cheapest
   high-impact first, and the one structural change that would prevent the class
   from recurring. Place MEDIUMs by real risk, not automatically last: a MEDIUM
   with a one-line fix in a file already being touched outranks a laborious HIGH.
9. **Limits of this analysis** — plainly: areas not reached
   (`coverage.unmapped`), findings that could not be verified and why, endpoints
   whose enforcement is out-of-band (`unverifiable`), `untraced` candidates needing
   a human, and MEDIUMs whose rating hinges on a disclosure hunt that found
   nothing. **Never** imply coverage you did not achieve.

Rules: **only findings that cleared the bar** appear here — the summary must not
become a back door for the noise the bar rejected. Every claim must be traceable to
a recorded finding or a `coverage_matrix` row; state severities as recorded (a
MEDIUM must read as a MEDIUM, with its precondition); and if there are no findings,
say so plainly and keep sections 1, 3, 7 and 9 — *"no findings that meet the
reporting bar"* over a repo of this size **is** the executive result, and the
coverage and limits sections are what make it credible.

## 9. Phase G — Persist the model (so next PR doesn't reanalyze)
The durable model + findings live under `knowledge_dir/` (not gitignored). In CI
this is committed/pushed to the `model/<target>` branch **by the CI job's bot**
(see `.github/workflows/analyze.yml`), never to the target repo. **You (Claude) do
not run `git commit` here** — persistence is the CI runner's step, or the user's
own choice locally. Just make sure the model + findings JSON are written under
`knowledge_dir/`.

## 10. Phase H — Cycle summary + cleanup (always)
```bash
# Janitor — enforce "advisory ⇔ reproduced": delete any advisory/PoC bundle NOT
# backed by a poc_verified finding (dry-run first, then apply). Run this EVERY
# cycle, so an advisory left over from a finding that later failed re-verification
# is swept:
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py gc-advisories            # preview
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py gc-advisories --apply     # remove orphans
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py notify "✅ security-forge cycle: {repo}@{short_commit} — {n_new} new, {n_verified} verified, {n_candidates} candidates, {n_fixed} mitigated, {n_advisories} advisories, {n_sent} sent."   # if report.cycle_summary
SECFORGE_TARGET_REPO="<url>" python scripts/pipeline.py nuke   # tear down Docker sandbox — ALWAYS
```
Confirm before stopping:
- **every** finding reached a terminal verdict (§7);
- every **advisory on disk maps to a `poc_verified` finding** — i.e. `gc-advisories`
  reported nothing left to remove. No advisory may exist without a bundle that
  reproduced via `verify-poc`;
- every **verified HIGH/CRITICAL** has BOTH an advisory file in
  `<knowledge_dir>/advisories/` (§8.5) AND a runnable PoC bundle in
  `<knowledge_dir>/poc/<slug>/` (§8.6) that passed `verify-poc` — MEDIUMs get
  neither, by design;
- every recorded **MEDIUM** appears in the executive summary's medium section with
  its precondition and promotion condition (§8.7);
- `<knowledge_dir>/EXECUTIVE_SUMMARY.md` was rewritten this cycle (§8.7) and its
  counts match the store;
- nothing below the bar was recorded, and every dismissal names its reason or
  false-positive filter.

Print a short final summary to stdout (counts by severity + finding ids by status +
advisory paths + PoC-folder paths with their two-command run line + the executive
summary path) and stop.
Do not loop — the scheduler / user / CI starts the next run.
