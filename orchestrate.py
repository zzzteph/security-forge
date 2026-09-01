#!/usr/bin/env python3
"""security-forge — per-repo orchestrator (scan a whole GitHub org, reliably).

Runs a DEDICATED headless Claude session for EACH repo, one at a time, with a
hard per-repo wall-clock timeout. Whatever a single session does — finishes,
stalls, gets killed by a platform safeguard, errors, or refuses — the orchestrator
kills it at the deadline, tears down the sandbox, records the outcome in the
durable DB, and moves on to the NEXT repo. It never stops for one repo.

Why this is reliable: the orchestrator is a plain subprocess manager that holds
*no model context*, so it can drain an entire org that no single Claude session
could. Each repo gets a fresh session that sees only that one repo — context
exhaustion, cross-repo bleed, and "it stopped after N" all go away. Failures are
bounded and isolated per repo, and every result lands in db/security-forge.db.

Usage:
  python orchestrate.py --repo https://github.com/owner/repo   # just ONE repo, then stop
  python orchestrate.py --org my-org            # sync the org, then drain it
  python orchestrate.py --user my-handle        # a user account instead of an org
  python orchestrate.py                          # drain whatever is already queued
  python orchestrate.py --org my-org --rescan    # re-analyze only the repos that changed
  python orchestrate.py --org my-org --dry-run   # show the plan, launch nothing

Each repo's session logs to logs/orch-<slug>-<ts>.log. Fully resumable: the DB
tracks analyzed/error/skipped, so re-running continues from what's left.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import re

ROOT = Path(__file__).resolve().parent
PY = sys.executable or "python"


def _path_segments(url: str) -> list[str]:
    """host/owner/repo path parts of a git URL or slug, creds/scheme/.git removed."""
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    elif s.startswith("git@"):
        s = s[len("git@"):].replace(":", "/", 1)
    if "@" in s:
        s = s.split("@", 1)[1]
    if s.endswith(".git"):
        s = s[:-4]
    return [p for p in s.strip("/").replace("\\", "/").split("/") if p]


def _looks_local(value: str) -> bool:
    """A LOCAL source folder rather than a remote URL — by shape (mirrors
    common.is_local_path so the orchestrator needn't import the scripts package)."""
    s = (value or "").strip()
    if not s:
        return False
    if s.startswith("file://"):
        return True
    if s in (".", "..") or s.startswith(("/", "./", "../", "~/", "~\\", ".\\", "..\\")):
        return True
    return bool(re.match(r"^[A-Za-z]:[\\/]", s)) or s.startswith("\\\\")


def normalize_model(m: str) -> str:
    """Turn a friendly model name into the id the Claude Code CLI accepts.
    Passes through bare aliases (opus/sonnet/haiku/default) and anything already
    starting 'claude-'. 'OPUS4.8' -> 'claude-opus-4-8', 'opus5[1m]' ->
    'claude-opus-5[1m]'. Unknown shapes are returned unchanged."""
    s = (m or "").strip()
    if not s:
        return s
    low = s.lower().replace(" ", "")
    if low in {"opus", "sonnet", "haiku", "default"} or low.startswith("claude-"):
        return s
    mt = re.match(r"^(opus|sonnet|haiku|fable)[-_.]?(\d+(?:\.\d+)?)?(\[1m\])?$", low)
    if mt:
        fam, ver, ctx = mt.group(1), mt.group(2), mt.group(3) or ""
        if not ver:
            return fam + ctx
        return f"claude-{fam}-{ver.replace('.', '-')}{ctx}"
    return s


def _helper_json(script: str, *args):
    """Run an orgdb.py subcommand and parse its JSON stdout (or None)."""
    r = subprocess.run([PY, str(ROOT / "scripts" / script), *args],
                       cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def orgdb(*a):
    return _helper_json("orgdb.py", *a)


def org(*a):
    return _helper_json("org.py", *a)


def pending_count(rescan: bool = False, known_only: bool = False) -> int:
    a = ["pending"] + (["--rescan"] if rescan else []) + (["--known-only"] if known_only else [])
    return int((orgdb(*a) or {}).get("pending", 0))


def next_targets(count: int, rescan: bool = False, known_only: bool = False) -> list:
    a = (["next-batch", "--count", str(count)]
         + (["--rescan"] if rescan else [])
         + (["--known-only"] if known_only else []))
    r = orgdb(*a)
    return [t for t in r if t.get("slug")] if isinstance(r, list) else []


def build_prompt(repo_url: str, slug: str, timeout: int) -> str:
    mins = max(1, timeout // 60)
    reserve = 3 if mins <= 45 else 5   # minutes to keep back for record + nuke
    return (
        f"You are analyzing EXACTLY ONE repository: {repo_url} (slug {slug}). "
        f"SECFORGE_TARGET_REPO is already set to it in your environment, so every "
        f"`python scripts/...` call keys to this repo. Follow opt/workflow.md end "
        f"to end for THIS repo only: run `python scripts/pipeline.py prep`, build/"
        f"refresh its model in knowledge/, hunt for real MEDIUM/HIGH/CRITICAL bugs, "
        f"verify every candidate in the container sandbox, write an advisory + "
        f"runnable PoC for each verified finding, then run "
        f"`python scripts/org.py record --repo {repo_url}` to fold the findings "
        f"into the DB and mark it analyzed, and finally `python scripts/verify.py "
        f"nuke`. Do NOT analyze any other repo, do NOT loop to a next repo, never "
        f"ask questions, keep everything local (notify-only). Stop as soon as this "
        f"one repo is recorded. "
        f"CRITICAL — HARD DEADLINE: this session is force-killed at ~{mins} minutes "
        f"of wall-clock; whatever is not written to the store by then is LOST. Plan "
        f"the whole cycle around that budget: "
        f"(1) RUN SYNCHRONOUSLY in THIS turn — never call ScheduleWakeup, never "
        f"defer work to a background agent and end your turn waiting for it to "
        f"report back; if you delegate to a subagent, wait for it to finish and "
        f"return WITHIN this turn, then continue. Do not pause, yield, or schedule "
        f"a continuation. "
        f"(2) CHECKPOINT AS YOU GO — `add-finding` each bug the MOMENT it clears the "
        f"bar, and `set-status` right after you verify it; never batch findings to "
        f"the end. A confirmed finding still sitting in your head when the deadline "
        f"hits is a finding lost, so persist early and often. "
        f"(3) BREADTH BEFORE DEPTH on a large repo — cap subagent fan-out to the "
        f"config budget (analysis.max_recon_agents / max_authz_agents / "
        f"max_analyzer_agents) and cover the highest-value areas first. It is FINE "
        f"to finish a cycle with only partial coverage recorded: the next "
        f"(incremental) run resumes from the persisted knowledge/ model, so do NOT "
        f"try to exhaustively analyze AND verify a huge codebase in a single cycle. "
        f"(4) LAND THE PLANE — keep the last ~{reserve} minutes to run BOTH `python "
        f"scripts/org.py record --repo {repo_url}` AND `python scripts/verify.py "
        f"nuke`. If time is running short, STOP hunting, record what you already "
        f"have, then record + nuke. Ending the turn cleanly with findings recorded "
        f"always beats being killed mid-analysis with the work unsaved. Your turn "
        f"MUST NOT end until BOTH record AND nuke have actually run for this repo."
    )


def _kill_tree(p: subprocess.Popen):
    """Hard-kill the session and any children (docker/podman etc.) it spawned."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    except Exception:
        pass
    try:
        p.wait(timeout=30)
    except Exception:
        pass


def _tail(path: Path, nbytes: int = 4096) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - nbytes))
            chunk = f.read().decode("utf-8", "replace")
        lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
        return lines[-1][:100] if lines else "(starting…)"
    except Exception:
        return ""


def _h(n: int) -> str:
    """Humanize a token count: 8423 -> '8.4k', 2_100_000 -> '2.1M'."""
    n = int(n or 0)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return str(n)


class _Progress:
    """Incrementally parses a session's stream-json log so the heartbeat can show
    what the model is actually doing — turns, tool calls, token usage, and the
    latest action — instead of a raw last line. Reads only bytes appended since
    the previous poll, so it stays cheap on long sessions."""

    def __init__(self, path: Path):
        self.path = path
        self.off = 0
        self.buf = ""
        self.turns = self.tools = 0
        self.tin = self.tout = self.cache = 0
        self.cost = None
        self.err = None
        self.last = "(starting…)"

    def _tool_str(self, c: dict) -> str:
        name = c.get("name", "tool")
        inp = c.get("input", {}) or {}
        arg = (inp.get("command") or inp.get("file_path") or inp.get("pattern")
               or inp.get("description") or inp.get("prompt") or "")
        arg = " ".join(str(arg).split())
        if len(arg) > 60:
            arg = arg[:57] + "…"
        return f"{name}: {arg}" if arg else name

    def _feed(self, line: str):
        line = line.strip()
        if not line:
            return
        try:
            ev = json.loads(line)
        except Exception:
            return
        t = ev.get("type")
        if t == "assistant":
            msg = ev.get("message", {}) or {}
            u = msg.get("usage", {}) or {}
            self.tin += int(u.get("input_tokens") or 0)
            self.tout += int(u.get("output_tokens") or 0)
            self.cache += int(u.get("cache_read_input_tokens") or 0)
            self.turns += 1
            tool = text = None
            for c in msg.get("content", []) or []:
                if not isinstance(c, dict):
                    continue
                if c.get("type") == "tool_use":
                    tool = c
                    self.tools += 1
                elif c.get("type") == "text" and (c.get("text") or "").strip():
                    text = c["text"].strip()
            if tool:
                self.last = self._tool_str(tool)
            elif text:
                self.last = "· " + " ".join(text.split())[:70]
        elif t == "result":
            self.cost = ev.get("total_cost_usd", self.cost)
            if ev.get("is_error") or ev.get("subtype") not in (None, "success"):
                self.err = ev.get("subtype") or "error"
        elif t == "system" and ev.get("subtype") == "init":
            self.last = "init — session started"

    def update(self) -> str:
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off)
                data = f.read()
                self.off = f.tell()
        except Exception:
            return self.status()
        if data:
            self.buf += data.decode("utf-8", "replace")
            *lines, self.buf = self.buf.split("\n")
            for ln in lines:
                self._feed(ln)
        return self.status()

    def status(self) -> str:
        cache = f" cache {_h(self.cache)}" if self.cache else ""
        return (f"turns={self.turns} tools={self.tools} "
                f"tok in {_h(self.tin)}/out {_h(self.tout)}{cache}  {self.last}")

    def summary(self) -> str:
        cost = f" cost=${self.cost:.2f}" if isinstance(self.cost, (int, float)) else ""
        err = f" ERROR={self.err}" if self.err else ""
        return (f"{self.turns} turns, {self.tools} tools, "
                f"tok in {_h(self.tin)}/out {_h(self.tout)}{cost}{err}")


class _TextProgress:
    """Fallback progress reader for a backend whose log is plain text (or a JSON
    shape we don't parse): count lines/bytes and echo the latest non-empty line.
    Same interface as `_Progress` so the heartbeat loop is backend-agnostic."""

    def __init__(self, path: Path):
        self.path = path
        self.off = 0
        self.buf = ""
        self.lines = 0
        self.nbytes = 0
        self.last = "(starting…)"
        self.err = None

    def update(self) -> str:
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off)
                data = f.read()
                self.off = f.tell()
        except OSError:
            return self.status()
        if data:
            self.nbytes += len(data)
            self.buf += data.decode("utf-8", "replace")
            *lines, self.buf = self.buf.split("\n")
            for ln in lines:
                s = ln.strip()
                if s:
                    self.lines += 1
                    self.last = s[:100]
        return self.status()

    def status(self) -> str:
        return f"lines={self.lines} {_h(self.nbytes)}B  {self.last}"

    def summary(self) -> str:
        return f"{self.lines} lines, {_h(self.nbytes)}B"


class AgentBackend:
    """Pluggable 'run one headless agentic session' backend. The orchestrator (queue,
    timeout, teardown, salvage) is backend-agnostic; a backend only knows how to
    LAUNCH the agent and how to READ its log for the heartbeat. `claude-code` is the
    default; `cli-adapter` wraps any other headless agentic CLI via a template."""

    name = "base"

    def build_command(self, prompt: str, model: str) -> list[str]:
        raise NotImplementedError

    def progress(self, log_path: Path):
        return _TextProgress(log_path)

    def normalize_model(self, model: str) -> str:
        return model

    def missing_hint(self, binary: str) -> str:
        return f"'{binary}' not found — check the {self.name} backend command/PATH."


class ClaudeCodeBackend(AgentBackend):
    name = "claude-code"

    def __init__(self, claude_bin: str):
        self.claude = claude_bin

    def build_command(self, prompt: str, model: str) -> list[str]:
        cmd = [self.claude, "-p", prompt, "--verbose", "--output-format",
               "stream-json", "--dangerously-skip-permissions"]
        if model:
            cmd += ["--model", model]
        return cmd

    def progress(self, log_path: Path):
        return _Progress(log_path)          # rich stream-json parser

    def normalize_model(self, model: str) -> str:
        return normalize_model(model)       # opus4.8 -> claude-opus-4-8

    def missing_hint(self, binary: str) -> str:
        return (f"'{binary}' not found — install Claude Code or pass --claude <path>.")


class CliAdapterBackend(AgentBackend):
    """Drive ANY headless agentic CLI (OpenAI Codex, Gemini CLI, aider, …) from a
    command TEMPLATE with `{prompt}` and `{model}` placeholders, e.g.:
        codex exec --model {model} --dangerously-bypass-approvals-and-sandbox {prompt}
        gemini -m {model} --yolo -p {prompt}
        aider --model {model} --yes --message {prompt}
    The template is split with shlex (so flags stay separate), then placeholders are
    substituted token-wise — `{prompt}` is replaced whole, so the (large) prompt
    stays ONE argv element and no shell is involved. Model passes through verbatim
    (gpt-5, gemini-2.5-pro, …). Provider keys come from the environment / .env."""

    name = "cli-adapter"

    def __init__(self, template: str, output: str = "text"):
        self.template = template
        self.output = (output or "text").lower()

    def build_command(self, prompt: str, model: str) -> list[str]:
        import shlex
        toks = shlex.split(self.template, posix=(os.name != "nt"))
        if not toks:
            raise SystemExit("[orch] cli-adapter: empty command template")
        out, saw_prompt = [], False
        for t in toks:
            t = t.replace("{model}", model or "")
            if "{prompt}" in t:
                saw_prompt = True
                t = t.replace("{prompt}", prompt)
            out.append(t)
        if not saw_prompt:                  # template omitted {prompt}: append it
            out.append(prompt)
        return out

    def progress(self, log_path: Path):
        # 'jsonl'/'stream-json' → the same event shape Claude Code emits; else text.
        if self.output in ("jsonl", "stream-json", "claude"):
            return _Progress(log_path)
        return _TextProgress(log_path)


class LiteLLMBackend(AgentBackend):
    """Native, CLI-free backend: runs `scripts/litellm_agent.py` (our own tool-use
    loop over LiteLLM) as the session subprocess. Works with any LiteLLM model
    string — openai/gpt-5, gemini/gemini-2.5-pro, anthropic/…, ollama/…, a local
    endpoint — with provider keys from the env / --agent-env. Emits Claude-style
    stream-json, so the heartbeat and salvage work exactly as for claude-code."""

    name = "litellm"

    def __init__(self, max_turns=None, temperature=None, max_context_tokens=None,
                 api_base=None):
        self.script = ROOT / "scripts" / "litellm_agent.py"
        self.max_turns = max_turns
        self.temperature = temperature
        self.max_context_tokens = max_context_tokens
        self.api_base = api_base

    def build_command(self, prompt: str, model: str) -> list[str]:
        cmd = [PY, str(self.script), "--model", model or "", "--prompt", prompt]
        if self.max_turns:
            cmd += ["--max-turns", str(self.max_turns)]
        if self.temperature is not None:
            cmd += ["--temperature", str(self.temperature)]
        if self.max_context_tokens:
            cmd += ["--max-context-tokens", str(self.max_context_tokens)]
        if self.api_base:
            cmd += ["--api-base", self.api_base]
        return cmd

    def progress(self, log_path: Path):
        return _Progress(log_path)          # emits Claude-style events

    def missing_hint(self, binary: str) -> str:
        return (f"python ('{binary}') not found for the litellm backend — it runs "
                f"scripts/litellm_agent.py (needs `pip install litellm`).")


def run_session(prompt: str, env_extra: dict, backend: AgentBackend, model: str,
                timeout: int, log_path: Path, heartbeat: int = 30,
                quiet: bool = False) -> int:
    """Launch one headless agent session (via `backend`), bounded by a hard timeout.
    Prints a heartbeat every `heartbeat`s. Returns the exit code, or 124 if killed
    at the deadline. Never raises (except a missing agent binary)."""
    cmd = backend.build_command(prompt, model)
    env = {**os.environ, **env_extra}
    popen_kw = {}
    if os.name == "posix":
        popen_kw["start_new_session"] = True
    else:
        popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    log = open(log_path, "w", encoding="utf-8", errors="replace")
    try:
        p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log,
                             stderr=subprocess.STDOUT, env=env, **popen_kw)
    except FileNotFoundError:
        log.close()
        print(f"[orch] FATAL: {backend.missing_hint(cmd[0])}", file=sys.stderr)
        raise SystemExit(2)
    start = time.monotonic()
    prog = backend.progress(log_path)
    rc = None
    try:
        while True:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                _kill_tree(p)
                rc = 124
                break
            try:
                rc = p.wait(timeout=min(heartbeat, remaining))
                break
            except subprocess.TimeoutExpired:
                el = int(time.monotonic() - start)
                if not quiet:
                    print(f"[orch]     .. {el // 60}m{el % 60:02d}s  {prog.update()}", flush=True)
    finally:
        log.close()
    prog.update()   # fold in whatever the session emitted since the last poll
    if not quiet:
        print(f"[orch]     -> {prog.summary()}", flush=True)
    return rc


def data_root() -> Path:
    return Path(os.environ.get("SECFORGE_DATA_DIR") or ROOT).expanduser().resolve()


def load_dotenv() -> None:
    """Load ROOT/.env into the environment (without overriding real env vars) so a
    non-Claude backend's provider keys (OPENAI_API_KEY, GEMINI_API_KEY, …) reach the
    child CLI even when they live in security-forge's .env rather than the shell."""
    p = ROOT / ".env"
    if not p.exists():
        return
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


def agent_config() -> dict:
    """The optional `agent:` block from config.yaml (backend/model/cli). Tolerant:
    returns {} if the file or PyYAML is missing, so the orchestrator never hard-
    depends on config just to launch the default Claude backend."""
    try:
        import yaml  # type: ignore
        p = ROOT / "config.yaml"
        if p.exists():
            return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("agent") or {}
    except Exception:  # noqa: BLE001  (missing yaml / malformed file → no agent cfg)
        pass
    return {}


def resolve_backend(args, cfg: dict) -> AgentBackend:
    """Pick the backend to run every session. Precedence: CLI flag > config.agent >
    default 'claude-code'. Beyond the two built-ins, `name` may select a NAMED
    PRESET from `config.yaml agent.backends.<name>` — your registry of agent
    'types' (codex / gemini / aider / a local model via LiteLLM-backed CLI, …),
    each a command template + output format. `--model` fills the template's
    `{model}`, so `--backend codex --model gpt-5` just works."""
    # Precedence: explicit --backend wins; else a CLI --agent-cmd implies the ad-hoc
    # cli-adapter (a command line signal beats the config default, so you can specify
    # a whole backend inline without touching config.yaml); else config; else default.
    if args.backend:
        name = args.backend.strip()
    elif args.agent_cmd:
        name = "cli-adapter"
    else:
        name = (cfg.get("backend") or "claude-code").strip()
    presets = cfg.get("backends") or {}

    if name == "claude-code":
        return ClaudeCodeBackend(args.claude)

    if name == "litellm":
        lc = cfg.get("litellm") or {}
        mt = args.agent_max_turns or lc.get("max_turns")
        temp = (args.agent_temperature if args.agent_temperature is not None
                else lc.get("temperature"))
        mct = lc.get("max_context_tokens")
        base = (args.agent_base_url or lc.get("api_base") or "").strip() or None
        return LiteLLMBackend(mt, temp, mct, base)

    if name == "cli-adapter":
        cli = cfg.get("cli") or {}
        template = (args.agent_cmd or cli.get("command") or "").strip()
        output = (args.agent_output or cli.get("output") or "text").strip()
    elif name in presets:                       # a named 'type' from the registry
        preset = presets[name] or {}
        template = (args.agent_cmd or preset.get("command") or "").strip()
        output = (args.agent_output or preset.get("output") or "text").strip()
    else:
        known = ", ".join(["claude-code", "cli-adapter", *sorted(presets)])
        print(f"[orch] FATAL: unknown --backend '{name}' (available: {known})",
              file=sys.stderr)
        raise SystemExit(2)

    if not template:
        print(f"[orch] FATAL: backend '{name}' needs a command template — pass "
              f"--agent-cmd '<cmd with {{prompt}} {{model}}>' or set it in "
              f"config.yaml (agent.cli.command or agent.backends.{name}.command).",
              file=sys.stderr)
        raise SystemExit(2)
    b = CliAdapterBackend(template, output)
    b.name = name                               # report the chosen type in logs
    return b


def process_repo(t: dict, args, logs: Path, idx: int, total) -> str:
    """Run one bounded session for a single repo, tear down, and return its final
    DB status. Shared by the org-drain loop and the single --repo path."""
    slug = t["slug"]
    repo_url = t.get("repo_url") or f"https://{slug}"
    ts = time.strftime("%Y%m%d-%H%M%S")
    log = logs / f"orch-{slug.replace('/', '-')}-{ts}.log"
    env_extra = {"SECFORGE_TARGET_REPO": repo_url, "SECFORGE_TARGET": slug}
    if os.environ.get("SECFORGE_DATA_DIR"):
        env_extra["SECFORGE_DATA_DIR"] = os.environ["SECFORGE_DATA_DIR"]
    env_extra.update(getattr(args, "_agent_env", {}))   # provider keys from --agent-env
    orgdb("set-status", "--slug", slug, "--status", "analyzing")
    print(f"[orch] ({idx}/{total}) {slug} → session (≤{args.timeout}s)  log: {log}",
          flush=True)
    t0 = time.monotonic()
    rc = run_session(build_prompt(repo_url, slug, args.timeout), env_extra,
                     args._backend, args.model, args.timeout, log, args.heartbeat,
                     args.silent)
    cleanup(slug, env_extra)
    orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
    row = orgdb("show", "--slug", slug) or {}
    st = row.get("status")
    salvaged = salvage_partial(repo_url, st)
    dt = int(time.monotonic() - t0)
    if st == "analyzed":
        print(f"[orch]   ✓ analyzed {(row.get('analyzed_commit') or '')[:8]} "
              f"(rc={rc}, {dt}s, MED={row.get('medium_count',0)} "
              f"HIGH={row.get('high_count',0)} CRIT={row.get('critical_count',0)})")
    elif st == "skipped":
        print(f"[orch]   ⤼ skipped after repeated aborts (rc={rc}, {dt}s)"
              f"{_salvage_str(salvaged)}")
    else:
        print(f"[orch]   ✗ not completed (status={st}, rc={rc}, {dt}s)"
              f"{_salvage_str(salvaged)} — retry next run")
    return st


def salvage_partial(repo_url: str, status: str | None) -> dict | None:
    """When a session is killed before it can run `org.py record` (a timeout, a
    crash, a platform safeguard), its findings still live in knowledge/<slug>/
    findings.json — cleanup() keeps knowledge/. Fold whatever it DID find into the
    DB so a partial run is never a total loss. `record --partial` syncs the
    findings + severity counts WITHOUT marking the repo analyzed, so it stays
    retryable next run. No-op for a repo that finished cleanly (already recorded)."""
    if status == "analyzed":
        return None
    sv = org("record", "--repo", repo_url, "--partial")
    return sv if isinstance(sv, dict) and sv.get("findings_synced") else None


def _salvage_str(sv: dict | None) -> str:
    if not sv:
        return ""
    return (f" — salvaged {sv.get('findings_synced', 0)} finding(s) "
            f"(MED={sv.get('medium', 0)} HIGH={sv.get('high', 0)} "
            f"CRIT={sv.get('critical', 0)})")


def cleanup(slug: str, env_extra: dict):
    """Guarantee teardown after every session: nuke the sandbox and wipe this
    repo's disposable clone + scratch so the next repo starts clean, even on a
    kill. knowledge/ (the durable model) and the DB are kept."""
    subprocess.run([PY, str(ROOT / "scripts" / "verify.py"), "nuke"],
                   cwd=str(ROOT), capture_output=True, text=True,
                   env={**os.environ, **env_extra})
    import shutil
    data = data_root()
    for sub in ("target", "state"):
        try:
            shutil.rmtree(data / sub / slug, ignore_errors=True)
        except Exception:
            pass


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--org", help="GitHub org to sync into the queue before "
                   "draining. Accepts a bare name (github.com), a 'host/owner' "
                   "key, or a full org URL — e.g. "
                   "https://github.example.com/my-org for GitHub Enterprise "
                   "Server (its API is <host>/api/v3).")
    g.add_argument("--user", help="GitHub user account (same host forms as --org)")
    g.add_argument("--repo", help="analyze a SINGLE repo URL (one session), then "
                   "stop. Also accepts a LOCAL folder path or file:// URL — the same "
                   "as --path.")
    g.add_argument("--path", help="analyze a SINGLE LOCAL source folder (one "
                   "session), then stop — a git repo is cloned (diffs work) or a "
                   "plain folder is copied. Keyed as local/<foldername>.")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="hard per-repo session timeout, seconds (default: 3600 = "
                         "1h). Verification-heavy targets (large Docker base images, "
                         "big repos) may need more — raise it, e.g. --timeout 7200 "
                         "for 2h. The per-repo session is told its budget and plans "
                         "around it (breadth-first, checkpoint findings, land record "
                         "+ nuke before the deadline).")
    ap.add_argument("--max-repos", type=int, default=0,
                    help="stop after N repos this run (0 = until the queue is empty)")
    ap.add_argument("--max-attempts", type=int, default=2,
                    help="skip a repo after this many aborted sessions across runs")
    ap.add_argument("--claude", default=os.environ.get("CLAUDE_BIN", "claude"),
                    help="path to the Claude Code CLI (default: claude); used by "
                         "the claude-code backend")
    ap.add_argument("--backend", default="",
                    help="which agent runs each session: 'claude-code' (default) or "
                         "'cli-adapter' to wrap any headless agentic CLI (OpenAI "
                         "Codex, Gemini CLI, aider, …). Overrides config.yaml "
                         "agent.backend.")
    ap.add_argument("--agent-cmd", default="",
                    help="cli-adapter: command TEMPLATE with {prompt} and {model} "
                         "placeholders, e.g. \"codex exec --model {model} "
                         "--dangerously-bypass-approvals-and-sandbox {prompt}\". "
                         "Overrides config.yaml agent.cli.command.")
    ap.add_argument("--agent-output", default="",
                    help="cli-adapter: 'text' (default) or 'jsonl' — how to read the "
                         "wrapped CLI's log for the progress heartbeat.")
    ap.add_argument("--agent-env", action="append", default=[], metavar="KEY=VALUE",
                    help="set an environment variable for the agent CLI (repeatable), "
                         "e.g. --agent-env OPENAI_API_KEY=sk-... --agent-env "
                         "OPENAI_BASE_URL=https://... . Lets you specify provider "
                         "keys/endpoints entirely on the command line instead of "
                         ".env; these override the inherited environment. Values are "
                         "never printed to the console.")
    ap.add_argument("--agent-max-turns", type=int, default=0,
                    help="litellm backend: max tool-use turns per session (0 = "
                         "default 500). The per-repo --timeout still bounds wall clock.")
    ap.add_argument("--agent-temperature", type=float, default=None,
                    help="litellm backend: sampling temperature (provider default if unset)")
    ap.add_argument("--agent-base-url", default="",
                    help="litellm backend: override the model endpoint URL (a "
                         "self-hosted OpenAI-compatible server, Ollama/vLLM, or a "
                         "LiteLLM proxy), e.g. http://localhost:4000 . The API key "
                         "still comes from the env (--agent-env OPENAI_API_KEY=… or "
                         "--agent-env SECFORGE_LLM_API_KEY=… for a generic endpoint).")
    ap.add_argument("--model", default="", help="optional model to pass through "
                    "(claude-code: normalized, e.g. opus4.8 -> claude-opus-4-8; "
                    "cli-adapter: passed verbatim, e.g. gpt-5, gemini-2.5-pro)")
    ap.add_argument("--heartbeat", type=int, default=30,
                    help="seconds between progress heartbeats (default: 30)")
    ap.add_argument("--silent", action="store_true",
                    help="suppress the live per-session progress (turns/tools/"
                         "tokens/current action + end-of-session summary). Progress "
                         "is shown by default; the full stream-json is always in "
                         "the session log either way.")
    ap.add_argument("--output-dir", default="",
                    help="folder for ALL artifacts (db, logs, knowledge, target, "
                         "state). Defaults to the repo folder; set this to keep "
                         "results out of the hidden ~/.claude/plugins cache. Sets "
                         "SECFORGE_DATA_DIR for every session it launches.")
    ap.add_argument("--no-sync", action="store_true",
                    help="skip the org sync (drain the DB as-is)")
    ap.add_argument("--rescan", action="store_true",
                    help="re-sync and re-queue already-analyzed repos whose upstream "
                         "changed since last analysis, then re-analyze just the diffs")
    ap.add_argument("--known-only", action="store_true",
                    help="re-check ONLY repos you've already analyzed (that have a "
                         "model in knowledge/) — your repos, NOT their whole orgs. "
                         "Skips all org discovery/sync; each session pulls latest and "
                         "analyzes just the diff. Use this (instead of --rescan) to "
                         "sync the latest for your known repos after a backfill.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and launch nothing")
    args = ap.parse_args()

    # Backend + model: resolve the agent BEFORE the model, since model normalization
    # is backend-specific (claude-code maps opus4.8 -> claude-opus-4-8; others pass
    # it through verbatim). Provider keys for non-Claude backends may live in .env.
    load_dotenv()
    acfg = agent_config()
    # Extra env for the agent CLI, straight from the command line (provider keys,
    # base URLs). Parsed once; merged into every session's environment. Never logged.
    args._agent_env = {}
    for kv in args.agent_env:
        if "=" not in kv:
            print(f"[orch] WARNING: ignoring --agent-env '{kv}' (need KEY=VALUE)",
                  file=sys.stderr)
            continue
        k, v = kv.split("=", 1)
        args._agent_env[k.strip()] = v
    args._backend = resolve_backend(args, acfg)
    if not args.model:
        args.model = (acfg.get("model") or "").strip()
    if args.model:
        norm = args._backend.normalize_model(args.model)
        if norm != args.model:
            print(f"[orch] model '{args.model}' -> '{norm}'", flush=True)
        args.model = norm
    if args._backend.name == "litellm" and not args.model:
        print("[orch] FATAL: the litellm backend needs a model — pass --model "
              "<litellm model> (e.g. openai/gpt-5, gemini/gemini-2.5-pro, "
              "ollama/llama3) or set config.yaml agent.model.", file=sys.stderr)
        raise SystemExit(2)
    _base = getattr(args._backend, "api_base", None)
    print(f"[orch] backend={args._backend.name}"
          f"{' model=' + args.model if args.model else ''}"
          f"{' base=' + _base if _base else ''}", flush=True)

    # `--rescan` with NO explicit --org/--user means "re-check the repos I already
    # analyzed" — NOT "re-list every org they belong to" (which discovers thousands
    # of unrelated repos). Fold it into known-only so the common `--rescan` is safe;
    # org-wide discovery stays opt-in via `--rescan --org OWNER` (or `--org OWNER`).
    if args.rescan and not (args.org or args.user) and not args.known_only:
        print("[orch] --rescan (no --org): re-checking only your analyzed repos "
              "(--known-only). For org-wide discovery use --rescan --org OWNER.",
              flush=True)
        args.known_only = True

    # Redirect all artifacts before anything touches the DB; children inherit it.
    if args.output_dir:
        os.environ["SECFORGE_DATA_DIR"] = str(Path(args.output_dir).expanduser().resolve())
    data = data_root()
    logs = data / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    print(f"[orch] artifacts -> {data}")

    orgdb("init")

    # Single-target mode: enqueue one repo/folder, run exactly one session, then stop.
    single = args.repo or args.path
    if single:
        is_local = bool(args.path) or _looks_local(single)
        if is_local:
            p = Path(single[len("file://"):] if single.startswith("file://")
                     else single).expanduser()
            if not p.is_dir():
                print(f"[orch] ERROR: local source folder not found: {p}",
                      file=sys.stderr)
                raise SystemExit(2)
            single = str(p.resolve())        # canonical path (stable slug + clone src)
        elif len(_path_segments(single)) < 3:
            segs = _path_segments(single)
            owner_url = single.rstrip("/")
            print(f"[orch] ERROR: --repo needs a full host/owner/repo URL, but "
                  f"'{single}' has no repo segment (parsed {'/'.join(segs) or '∅'}). "
                  f"For a LOCAL folder use --path <dir>.", file=sys.stderr)
            if len(segs) == 2:
                print(f"[orch]        '{segs[1]}' looks like an org/user. To scan "
                      f"all its repos use:\n"
                      f"[orch]          python orchestrate.py --org {owner_url}"
                      f"{(' --model ' + args.model) if args.model else ''}",
                      file=sys.stderr)
            raise SystemExit(2)
        if not args.dry_run:
            orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
        row = orgdb("add", "--repo", single) or {"slug": single, "repo_url": single}
        slug = row.get("slug") or single
        if args.dry_run:
            kind = "local folder" if is_local else "repo"
            print(f"[orch] (1) would analyze single {kind} {single} (slug {slug})")
            return
        print(f"[orch] single-target mode ({'local folder' if is_local else 'repo'}); "
              f"heartbeat every {args.heartbeat}s; tail -f {logs}/orch-*.log", flush=True)
        st = process_repo(row, args, logs, 1, 1)
        print(f"\n[orch] done. {slug} -> {st}")
        return

    extra = (["--include-forks"] if args.include_forks else []) + \
            (["--include-archived"] if args.include_archived else [])
    if not args.dry_run:
        orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
        if args.known_only:
            # Re-check only repos already analyzed (a model in knowledge/). Sync the
            # durable knowledge/ into the DB first (idempotent — works on a fresh box
            # or after a DB wipe), then re-check exactly those. NO org discovery, so
            # a repo's whole org is never pulled in.
            bf = orgdb("backfill") or {}
            if bf.get("targets"):
                print(f"[orch] known-only: {bf['targets']} analyzed repo(s) from "
                      f"knowledge/ ({bf.get('findings_synced', 0)} findings) — "
                      f"re-checking just these, not re-listing their orgs.", flush=True)
            else:
                print("[orch] known-only: no analyzed repos in knowledge/ to re-check "
                      "— run `--org OWNER` (or `--repo`/`--path`) to analyze some first.",
                      flush=True)
        elif (args.org or args.user) and not args.no_sync:
            who = ["--org", args.org] if args.org else ["--user", args.user]
            s = org("sync", *who, *extra) or {}
            print(f"[orch] synced {s.get('kind','?')} "
                  f"{s.get('owner', args.org or args.user)}"
                  f"{' @ ' + s['host'] if s.get('host') and s['host'] != 'github.com' else ''}: "
                  f"listed={s.get('listed','?')} queued={s.get('queued','?')} "
                  f"filtered_out={s.get('filtered_out','?')} "
                  f"(archived={s.get('skipped_archived',0)} forks={s.get('skipped_forks',0)})")

    total = pending_count(rescan=args.rescan, known_only=args.known_only)
    mode = ("known-only (re-check analyzed)" if args.known_only
            else "rescan (new + changed)" if args.rescan else "sweep (new only)")
    print(f"[orch] mode={mode} pending={total} timeout={args.timeout}s"
          f"{' (DRY-RUN)' if args.dry_run else ''}")
    if not args.dry_run:
        print(f"[orch] heartbeat every {args.heartbeat}s; watch a session live with:  "
              f"tail -f {logs}/orch-*.log", flush=True)

    attempted, analyzed, errored, skipped, n = set(), 0, 0, 0, 0
    while True:
        if args.max_repos and n >= args.max_repos:
            break
        batch = [t for t in next_targets(200, rescan=args.rescan, known_only=args.known_only)
                 if t.get("slug") not in attempted]
        if not batch:
            break
        for t in batch:
            if args.max_repos and n >= args.max_repos:
                break
            attempted.add(t["slug"])
            n += 1
            if args.dry_run:
                print(f"[orch] ({n}) would analyze {t['slug']}")
                continue
            st = process_repo(t, args, logs, n, total)
            analyzed += st == "analyzed"
            skipped += st == "skipped"
            errored += st not in ("analyzed", "skipped")

    print(f"\n[orch] done. sessions={n} analyzed={analyzed} "
          f"error(retry later)={errored} skipped={skipped} "
          f"remaining≈{pending_count(rescan=args.rescan, known_only=args.known_only)}")


if __name__ == "__main__":
    main()
