#!/usr/bin/env python3
"""security-forge — native LiteLLM agent (no external agentic CLI required).

This is the `litellm` backend's actual agent: a self-contained tool-use loop that
lets ANY LiteLLM-supported model (OpenAI, Gemini, Anthropic API, Azure, Bedrock,
a local Ollama/vLLM endpoint, …) drive a security-forge session directly — no
Claude Code, no Codex/Gemini/aider CLI in the middle. The orchestrator launches
this as a subprocess exactly like any other backend, so the hard per-repo timeout,
process-tree kill, teardown, and partial-findings salvage all still apply.

How it works: we hand the model a small set of tools — `bash`, `read_file`,
`write_file` — and loop `litellm.completion` → execute the tool calls in the
security-forge working dir → feed results back → repeat, until the model stops
calling tools (it's done) or the turn/context budget is hit. Progress is emitted
to stdout as Claude-style stream-json events so the orchestrator's heartbeat shows
turns / tools / tokens with no special-casing.

There are no subagents here — a single agent does every role inline, exactly as
opt/workflow.md specifies for the "no Agent tool" fallback.

Model + keys: `--model` is a LiteLLM model string (e.g. `openai/gpt-5`,
`gemini/gemini-2.5-pro`, `anthropic/claude-3-7-sonnet`, `ollama/llama3`); provider
keys come from the environment (the orchestrator forwards .env / --agent-env).

Install: `pip install litellm` (kept optional — this file is only imported when the
litellm backend is selected).

Usage (normally invoked by orchestrate.py, not by hand):
    python scripts/litellm_agent.py --model openai/gpt-5 --prompt "<task>" \
        [--max-turns 500] [--temperature 0.2] [--max-context-tokens 120000]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent   # security-forge home (SECFORGE_HOME)

SYSTEM = (
    "You are security-forge's autonomous security-analysis agent. You accomplish the "
    "user's task ENTIRELY by using your tools (bash, read_file, write_file) — never "
    "claim to have run, read, or written something you did not. Work synchronously in "
    "one pass and keep going until the task is fully done, then reply with a short "
    "final summary and STOP. You have no subagents: do each analysis role's work "
    "inline yourself. Prefer the provided scripts/ helpers (python scripts/pipeline.py, "
    "verify.py, org.py) over ad-hoc commands. Never ask the user questions — if "
    "something is ambiguous, make a reasonable choice, note it, and continue. "
    "When you record a finding (add-finding), NEVER a one-liner: always include "
    "description, impact (what an attacker concretely gains), root_cause (the exact "
    "code/config that is wrong and WHY), remediation (the specific fix), and "
    "reachability (entry point -> how untrusted input reaches the sink)."
)

# --- tool schemas (OpenAI function-calling format; LiteLLM normalizes per provider) --
TOOLS_SCHEMA = [
    {"type": "function", "function": {
        "name": "bash",
        "description": ("Run a shell command in the security-forge working directory "
                        "and return combined stdout+stderr and the exit code. The "
                        "shell (bash vs native Windows cmd.exe) and available tools "
                        "are stated in the EXECUTION ENVIRONMENT note in the system "
                        "prompt — follow it (e.g. no bash heredocs in native mode)."),
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "the shell command to run"},
            "timeout": {"type": "integer", "description": "max seconds (default 1200)"},
        }, "required": ["command"]}}},
    {"type": "function", "function": {
        "name": "read_file",
        "description": "Read a UTF-8 text file (optionally a line range).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "offset": {"type": "integer", "description": "0-based first line"},
            "limit": {"type": "integer", "description": "max lines"},
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Create or overwrite a UTF-8 text file with the given content.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"},
        }, "required": ["path", "content"]}}},
]


def emit(obj: dict) -> None:
    """Write one Claude-style stream-json event so the orchestrator heartbeat can
    parse turns/tools/tokens from our log."""
    try:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception:  # noqa: BLE001  (a logging hiccup must never kill the run)
        pass


def _cap(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n] + f"\n…[truncated {len(s) - n} chars]"


def _resolve(path: str) -> Path:
    p = Path(path).expanduser()
    return p if p.is_absolute() else (ROOT / p)


def _git_bash() -> str | None:
    """Locate GIT BASH (bundled with Git for Windows: git+grep+coreutils+POSIX),
    derived from the git install so we never pick WSL bash — often first on PATH but
    with NO git (causes clone 'No such file or directory: git')."""
    import shutil
    cands: list[Path] = []
    gitexe = shutil.which("git")
    if gitexe:
        base = Path(gitexe).resolve().parent.parent
        cands += [base / "bin" / "bash.exe", base / "usr" / "bin" / "bash.exe"]
    cands += [Path(r"C:\Program Files\Git\bin\bash.exe"),
              Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
              Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "bin" / "bash.exe"]
    for c in cands:
        try:
            if c.is_file():
                return str(c)
        except Exception:  # noqa: BLE001
            pass
    return None


_PROBE_TOOLS = ["git", "python", "grep", "rg", "curl", "tar", "sed", "awk",
                "docker", "podman", "findstr", "powershell"]


def _detect_caps() -> dict:
    """Pick a shell that can run the pipeline (clones with git): Git Bash
    (git+grep+POSIX) -> native cmd (if native git) -> other bash. Never a bash
    lacking git."""
    import shutil
    import platform as _plat
    native = {t: shutil.which(t) for t in _PROBE_TOOLS}
    native["python"] = native["python"] or sys.executable
    gitbash = _git_bash()
    other_bash = shutil.which("bash")
    if gitbash:
        mode, shell_exe = "bash", gitbash
    elif native.get("git"):
        mode, shell_exe = "native", None
    elif other_bash:
        mode, shell_exe = "bash", other_bash
    else:
        mode, shell_exe = "native", None
    return {"os": _plat.system(), "mode": mode, "shell_exe": shell_exe,
            "gitbash": gitbash, "native": {k: bool(v) for k, v in native.items()}}


_CAPS = _detect_caps()


def capability_report() -> str:
    n = _CAPS["native"]
    avail = " ".join(f"{t}={'y' if n.get(t) else 'n'}" for t in _PROBE_TOOLS)
    return (f"[litellm-agent] env: os={_CAPS['os']} shell-mode={_CAPS['mode']} "
            f"bash={'y' if _CAPS['shell_exe'] else 'n'} | native: {avail}")


def capability_note() -> str:
    n = _CAPS["native"]
    have = ", ".join(t for t in _PROBE_TOOLS if n.get(t)) or "(minimal)"
    miss = ", ".join(t for t in _PROBE_TOOLS if not n.get(t)) or "none"
    if _CAPS["mode"] == "bash":
        shell = ("Your `bash` tool runs in BASH (POSIX): pipes, heredocs, &&, "
                 "grep -rn all work. Prefer grep -rn; rg may be absent. Forward-slash paths.")
    else:
        shell = ("Your `bash` tool runs in NATIVE Windows cmd.exe: NO heredocs; use "
                 "`findstr /s /n` to search, `python -c \"...\"` or write_file (never "
                 "`<<`), PowerShell via `powershell -Command`.")
    return (f"EXECUTION ENVIRONMENT: os={_CAPS['os']}, shell-mode={_CAPS['mode']}. "
            f"{shell} Tools native: {have}. Missing native: {miss}.")


def tool_bash(args: dict) -> str:
    cmd = args.get("command", "")
    if not cmd.strip():
        return "[error: empty command]"
    to = max(1, min(int(args.get("timeout") or 1200), 3300))
    if _CAPS["mode"] == "bash" and _CAPS.get("shell_exe"):
        argv, shell = [_CAPS["shell_exe"], "-c", cmd], False
    else:
        argv, shell = cmd, True
    try:
        p = subprocess.run(argv, shell=shell, cwd=str(ROOT), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=to,
                           stdin=subprocess.DEVNULL)
        out = p.stdout or ""
        if p.stderr:
            out += ("\n[stderr]\n" + p.stderr)
        return f"exit={p.returncode}\n{_cap(out, 12000)}"
    except subprocess.TimeoutExpired:
        return f"[timeout after {to}s]"
    except Exception as e:  # noqa: BLE001
        return f"[error running command: {e}]"


def tool_read_file(args: dict) -> str:
    p = _resolve(args.get("path", ""))
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001
        return f"[error reading {p}: {e}]"
    off = int(args.get("offset") or 0)
    lim = args.get("limit")
    if off or lim:
        lines = text.splitlines()
        text = "\n".join(lines[off: off + int(lim) if lim else None])
    return _cap(text, 12000)


def tool_write_file(args: dict) -> str:
    p = _resolve(args.get("path", ""))
    content = args.get("content", "")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"wrote {p} ({len(content)} bytes)"
    except Exception as e:  # noqa: BLE001
        return f"[error writing {p}: {e}]"


DISPATCH = {"bash": tool_bash, "read_file": tool_read_file, "write_file": tool_write_file}


def _est_tokens(messages: list) -> int:
    """Cheap char/4 token estimate for context budgeting."""
    try:
        return sum(len(json.dumps(m, ensure_ascii=False, default=str)) for m in messages) // 4
    except Exception:  # noqa: BLE001
        return 0


def _compact(messages: list, keep_tokens: int) -> list:
    """Keep the conversation under a context budget without breaking the tool-call
    protocol. Always keep the system message and the initial instructions; keep the
    most recent messages up to the budget; and never let the kept window START with
    an orphan `tool` message (whose parent assistant tool_call was dropped)."""
    if len(messages) <= 3 or _est_tokens(messages) <= keep_tokens:
        return messages
    head, tail = messages[:2], messages[2:]
    kept: list = []
    total = _est_tokens(head)
    for m in reversed(tail):
        t = _est_tokens([m])
        if kept and total + t > keep_tokens:
            break
        kept.append(m)
        total += t
    kept.reverse()
    while kept and kept[0].get("role") == "tool":   # drop orphan tool replies
        kept.pop(0)
    note = {"role": "user", "content": "[Context trimmed: earlier tool output omitted "
            "to fit the model's context window. Durable state is on disk under "
            "knowledge/ and the findings store — re-read files as needed.]"}
    return head + [note] + kept


def _load_prompt(a) -> str:
    if a.prompt_file:
        return Path(a.prompt_file).read_text(encoding="utf-8")
    return a.prompt or ""


# --- reasoning effort: one friendly scale, mapped per model family ----------
# The UI exposes normal/high/max; each maps to the selected model's native knob.
# Anthropic/Claude -> output_config.effort (the extended high<xhigh<max scale, GA on
# Opus 4.7+/5, Sonnet 5, Fable 5; API default 'high'). OpenAI and everything else ->
# reasoning_effort (minimal|low|medium|high — no xhigh/max, so both high and max map
# to 'high'). Unsupported knobs are dropped (litellm.drop_params) or relaxed on error,
# so this never breaks a model that has no reasoning control.
_EFFORT = {
    "anthropic": {"low": "low", "medium": "medium", "normal": "high", "high": "xhigh", "max": "max"},
    "openai":    {"low": "low", "medium": "medium", "normal": "medium", "high": "high", "max": "high"},
}


def _effort_kwargs(model: str, level: str) -> dict:
    """Map a friendly effort level to litellm.completion kwargs for `model`. Returns
    {} for an empty/'off' level or a family with no mapping."""
    level = (level or "").strip().lower()
    if level in ("", "off", "none", "default"):
        return {}
    m = (model or "").lower()
    if "anthropic" in m or "claude" in m:
        val = _EFFORT["anthropic"].get(level)
        return {"output_config": {"effort": val}} if val else {}
    val = _EFFORT["openai"].get(level)          # OpenAI + generic fallback
    return {"reasoning_effort": val} if val else {}


# --- subagent fan-out: give the flat loop breadth via focused specialists -----
# Claude Code's depth comes from delegating each hot area to a specialist subagent
# with its own fresh context. The litellm backend has no such harness, so we add a
# minimal one: a `spawn_agent` tool the ROOT session can call to run a focused
# sub-loop (recon / authz / dataflow / logic / verify), each a fresh context sharing
# the same bash/read_file/write_file tools. Subagents cannot spawn (depth 1) and a
# per-run budget caps cost. Sequential, in-process; results return to the root as text.
_LLM = None                    # the litellm module (set in main)
_RUN: dict = {}                # runtime config shared by root + subagents
_TOTALS = {"cost": 0.0, "tin": 0, "tout": 0}
_SPAWN_BUDGET = {"left": 0}

_SPECIALISTS = {
    "recon": ("You are a RECON specialist. EXHAUSTIVELY enumerate the attack surface - "
              "omit NOTHING. Grep for EVERY endpoint registration (MapGet/MapPost/MapPut/"
              "MapDelete/MapMethods/MapGroup, [HttpGet]/[Route], controllers, minimal-API "
              "groups) AND every non-HTTP entry (queue/SQS/Kafka consumers, scheduled/"
              "Quartz jobs, and background / download / export / report / admin / internal "
              "endpoints, which are the ones most often forgotten). List each as "
              "method+path+handler with file:line, plus the roles/principals and how "
              "authn/authz work. Return a COMPLETE inventory; do NOT report vulnerabilities."),
    "authz": ("You are an ACCESS-CONTROL specialist. Walk the COMPLETE endpoint inventory "
              "from recon and, for EVERY endpoint, state whether a per-object ownership / "
              "per-tenant scope check exists and where (file:line) - do not stop at the "
              "obvious routes. Find missing authentication, broken function-level authz "
              "(privilege escalation), broken object-level authz (IDOR/BOLA), mass-"
              "assignment, and tenant/cross-scope isolation gaps. Explicitly audit these "
              "frequently-missed cross-scope sinks: (1) list/enumerate-all endpoints that "
              "return other tenants' records or ids, (2) fetch/download/export-by-id, "
              "(3) job/batch/report/task management (create/list/cancel/delete/status by "
              "runId/jobId - check the caller is scoped to that job), (4) admin/internal/"
              "debug endpoints. Flag ANY endpoint lacking an ownership or tenant-scope "
              "check. For each: file:line, the two-principal reasoning (attacker vs victim "
              "object), and a PoC sketch."),
    "dataflow": ("You are a DATA-FLOW / injection specialist. Trace untrusted input "
                 "from real entry points to dangerous sinks: SQL/NoSQL injection, "
                 "command injection, SSTI, XSS, path traversal, insecure "
                 "deserialization, SSRF. Report only reachable flows, each with an "
                 "explicit source->sink argument, file:line, and a PoC sketch."),
    "logic": ("You are a BUSINESS-LOGIC specialist. On every state-changing path find "
              "broken invariants (negative/oversized amounts, total/price tampering, "
              "min>max, arithmetic abuse), illegal state transitions, broken "
              "idempotency / replay of money actions, quota/limit bypass, and "
              "check-then-act (TOCTOU). Give the source->state-mutation trace, the "
              "enforcement-gap argument, and a request-sequence PoC sketch."),
    "verify": ("You are a VERIFICATION specialist. Given a candidate finding, read the "
               "real code along the hypothesized path and judge whether it truly holds "
               "(reachable, exploitable, not already mitigated). Static only, no "
               "Docker/DAST. Return CONFIRMED or DISMISSED with file:line evidence."),
    "generic": ("You are a focused security sub-analyst. Do exactly the task you are "
                "given, read the real code for evidence (file:line), and return a "
                "concise, concrete result."),
}

_DELEGATION_NOTE = (
    "DELEGATION: you have a `spawn_agent` tool. To get BREADTH without bloating this "
    "context, delegate each hot area to a fresh specialist instead of skimming it "
    "yourself: after recon, spawn one subagent per dimension (authz, dataflow/"
    "injection, business-logic, and any others the target warrants), give each a "
    "precise task naming the files/areas to examine, then SYNTHESIZE their reports, "
    "dedupe, and record the findings per the workflow. Subagents cannot spawn, so plan "
    "the fan-out yourself. Prefer delegating over a shallow single-pass read.")

_SPAWN_TOOL = {"type": "function", "function": {
    "name": "spawn_agent",
    "description": ("Delegate a focused security sub-analysis to a FRESH specialist "
                    "agent with its own context (it shares bash/read_file/write_file). "
                    "Cover breadth by spawning one per hot area (recon, authz, "
                    "dataflow, logic, verify), each with precise instructions, then "
                    "synthesize. Returns the subagent's findings as text."),
    "parameters": {"type": "object", "properties": {
        "focus": {"type": "string",
                  "enum": ["recon", "authz", "dataflow", "logic", "verify", "generic"],
                  "description": "which specialist lens to apply"},
        "task": {"type": "string",
                 "description": "precise instructions incl. which files/areas to examine"}},
        "required": ["focus", "task"]}}}

TOOLS_SCHEMA_ROOT = TOOLS_SCHEMA + [_SPAWN_TOOL]


def _complete(messages: list, tools_schema: list):
    """One litellm completion with the effort knob, relaxed if the provider rejects it.
    Shared by the root loop and every subagent (reads/updates _RUN)."""
    for _try in range(4):
        kw = dict(_RUN["extra"])
        if _RUN["effort_kw"]:
            kw.update(_RUN["effort_kw"])
        elif _RUN["re_effort"]:
            kw["reasoning_effort"] = _RUN["re_effort"]
        try:
            return _LLM.completion(model=_RUN["model"], messages=messages,
                                   tools=tools_schema, tool_choice="auto",
                                   temperature=_RUN["temperature"], num_retries=2, **kw)
        except Exception as e:  # noqa: BLE001
            low = str(e).lower()
            if _RUN["effort_kw"] and any(k in low for k in ("effort", "output_config", "reasoning")):
                emit({"type": "system", "subtype": "effort_unsupported", "detail": str(e)[:160]})
                _RUN["effort_kw"] = {}
                continue
            if "reasoning_effort" not in low:
                raise
            re = _RUN["re_effort"]
            if "does not support 'none'" in low or ("supported values" in low and re == "none"):
                _RUN["re_effort"] = "minimal"
            elif "set reasoning_effort to 'none'" in low or "are not supported" in low:
                _RUN["re_effort"] = "none"
            elif re:
                _RUN["re_effort"] = ""
            else:
                raise
    return _LLM.completion(model=_RUN["model"], messages=messages, tools=tools_schema,
                           tool_choice="auto", temperature=_RUN["temperature"],
                           num_retries=2, **_RUN["extra"])


def _agent_loop(messages: list, tools_schema: list, max_turns: int, agent=None):
    """One tool-use session (root when agent is None, else a labelled subagent). Emits
    Claude-schema progress events, accumulates tokens/cost into _TOTALS, and returns
    (final_text, subtype). Never emits the final 'result' event."""
    final_text = ""
    for _turn in range(max(1, max_turns)):
        messages[:] = _compact(messages, _RUN["max_context_tokens"])
        try:
            resp = _complete(messages, tools_schema)
        except Exception as e:  # noqa: BLE001
            emit({"type": "assistant", "agent": agent, "message": {"content": [
                {"type": "text", "text": f"[completion error: {e}]"}]}})
            return (f"[completion error: {e}]", "error_during_execution")
        msg = resp.choices[0].message
        usage = getattr(resp, "usage", None)
        tool_calls = list(getattr(msg, "tool_calls", None) or [])
        _TOTALS["tin"] += int(getattr(usage, "prompt_tokens", 0) or 0)
        _TOTALS["tout"] += int(getattr(usage, "completion_tokens", 0) or 0)
        try:
            _TOTALS["cost"] += _LLM.completion_cost(completion_response=resp) or 0.0
        except Exception:  # noqa: BLE001
            _TOTALS["cost"] += float((getattr(resp, "_hidden_params", {}) or {}).get("response_cost") or 0.0)
        blocks: list = []
        if getattr(msg, "content", None):
            final_text = str(msg.content)
            blocks.append({"type": "text", "text": str(msg.content)[:400]})
        for tc in tool_calls:
            try:
                inp = json.loads(tc.function.arguments or "{}")
            except Exception:  # noqa: BLE001
                inp = {"_raw": tc.function.arguments}
            blocks.append({"type": "tool_use", "name": tc.function.name, "input": inp})
        emit({"type": "assistant", "agent": agent, "message": {
            "usage": {"input_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                      "output_tokens": int(getattr(usage, "completion_tokens", 0) or 0)},
            "content": blocks}})
        am: dict = {"role": "assistant"}
        if getattr(msg, "content", None):
            am["content"] = msg.content
        if tool_calls:
            am["tool_calls"] = [{"id": tc.id, "type": "function",
                                 "function": {"name": tc.function.name,
                                              "arguments": tc.function.arguments}}
                                for tc in tool_calls]
        messages.append(am)
        if not tool_calls:
            return (final_text, "success")
        for tc in tool_calls:
            name = tc.function.name
            try:
                inp = json.loads(tc.function.arguments or "{}")
            except Exception:  # noqa: BLE001
                inp = {}
            fn = DISPATCH.get(name)
            result = fn(inp) if fn else f"[unknown tool: {name}]"
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": str(result)})
            emit({"type": "tool_result", "name": name, "agent": agent,
                  "output": _cap(str(result), 800)})
    return (final_text, "error_max_turns")


def tool_spawn_agent(args: dict) -> str:
    """spawn_agent tool: run a focused specialist sub-loop and return its report."""
    focus = (args.get("focus") or "generic").strip().lower()
    task = (args.get("task") or "").strip()
    if not task:
        return "[spawn_agent error: 'task' is required]"
    if _SPAWN_BUDGET["left"] <= 0:
        return ("[spawn_agent: subagent budget exhausted for this run - analyze this "
                "dimension yourself in the current context]")
    _SPAWN_BUDGET["left"] -= 1
    sys_prompt = _SPECIALISTS.get(focus, _SPECIALISTS["generic"])
    emit({"type": "system", "subtype": "subagent_start", "focus": focus,
          "budget_left": _SPAWN_BUDGET["left"], "task": task[:200]})
    msgs = [{"role": "system", "content": sys_prompt + "\n\n" + capability_note()},
            {"role": "user", "content": task}]
    text, subtype = _agent_loop(msgs, TOOLS_SCHEMA, _RUN["sub_turns"], agent=focus)
    emit({"type": "system", "subtype": "subagent_done", "focus": focus, "status": subtype})
    return (f"[subagent:{focus} -> {subtype}]\n\n{text}" if text
            else f"[subagent:{focus} finished ({subtype}) with no summary]")


DISPATCH["spawn_agent"] = tool_spawn_agent


def _forced_fanout(base_prompt: str, root_max_turns: int):
    """Deterministic fan-out (the litellm backend's default): always run recon, then
    the authz / dataflow / logic specialists, then let the root synthesize and record.
    Gives Claude-style reliable breadth instead of leaving delegation to the model's
    discretion. Returns (final_text, subtype) from the root coordinator session."""
    recon_map = ""
    reports = []
    for focus in ["recon", "authz", "dataflow", "logic"]:
        if _SPAWN_BUDGET["left"] <= 0:
            break
        ctx = base_prompt
        if focus != "recon" and recon_map:
            ctx += "\n\n=== RECON MAP (from the recon subagent) ===\n" + recon_map
        task = (ctx + "\n\n=== YOUR ASSIGNMENT ===\n"
                "Apply ONLY your specialty to this target and return your result as text. "
                "Do NOT run any recording/org commands and do NOT mark the repo analyzed "
                "- the coordinator will dedupe and record. Give concrete file:line "
                "evidence and a PoC sketch for each finding.")
        out = tool_spawn_agent({"focus": focus, "task": task})
        if focus == "recon":
            recon_map = out
        else:
            reports.append(out)
    synthesis = (base_prompt + "\n\n=== SPECIALIST SUBAGENT REPORTS ===\n"
                 + "\n\n".join(reports)
                 + "\n\n=== NOW, AS COORDINATOR ===\n"
                 "Synthesize the reports above, dedupe, and drop false positives. Then "
                 "CHECK COVERAGE before recording: confirm EVERY endpoint in the recon "
                 "inventory was assessed for an ownership/tenant-scope check - if the "
                 "authz report skipped any (especially list/enumerate-all, download/"
                 "export-by-id, job/batch/report management by runId/jobId, or admin/"
                 "internal endpoints), examine those yourself now and add any finding. "
                 "Finally RECORD the real findings into the store exactly as the workflow "
                 "instructs (run the recording command), then print the final summary.")
    msgs = [{"role": "system", "content": SYSTEM + "\n\n" + capability_note()},
            {"role": "user", "content": synthesis}]
    return _agent_loop(msgs, TOOLS_SCHEMA, root_max_turns, agent=None)


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="security-forge native LiteLLM agent")
    ap.add_argument("--model", required=True, help="LiteLLM model string, e.g. openai/gpt-5")
    ap.add_argument("--prompt", default="")
    ap.add_argument("--prompt-file", default="")
    ap.add_argument("--max-turns", type=int, default=500)
    ap.add_argument("--temperature", type=float, default=None)
    ap.add_argument("--max-context-tokens", type=int, default=120000)
    ap.add_argument("--api-base", default="", help="override the model endpoint URL "
                    "(self-hosted OpenAI-compatible server, Ollama/vLLM, or a LiteLLM "
                    "proxy). The API key still comes from the environment "
                    "(provider var, or SECFORGE_LLM_API_KEY for a generic endpoint).")
    ap.add_argument("--reasoning-effort", default="none",
                    help="raw reasoning_effort per completion (default 'none'; adapts if "
                         "a model rejects it). '' to omit. Used only when --effort is off.")
    ap.add_argument("--effort", default="max",
                    help="friendly reasoning level normal|high|max, mapped per model "
                         "(Anthropic output_config.effort high/xhigh/max; others "
                         "reasoning_effort medium/high/high). Default 'max'; '' disables. "
                         "Takes precedence over --reasoning-effort.")
    ap.add_argument("--max-subagents", type=int, default=6,
                    help="litellm depth: max specialist subagents the root may "
                         "spawn per run (0 = classic flat single loop).")
    ap.add_argument("--subagent-turns", type=int, default=40,
                    help="max tool-use turns per spawned subagent.")
    ap.add_argument("--fanout", default="forced", choices=["forced", "auto", "off"],
                    help="litellm depth strategy: 'forced' (default) "
                         "deterministically spawns recon+authz+dataflow+logic like "
                         "Claude; 'auto' lets the model decide; 'off' = flat loop.")
    a = ap.parse_args()

    # Through an OpenAI-compatible gateway (--api-base), EVERY model must go via
    # litellm's `openai/` provider (gateway group name follows). Without it a
    # `bedrock/…` group name makes litellm call AWS directly ('NoneType ... access_key').
    if a.api_base and a.model and not a.model.startswith("openai/"):
        a.model = "openai/" + a.model

    # Extra per-call kwargs. api_base is not secret (a flag); the key is read from
    # the environment so it never lands in argv / a process listing.
    extra: dict = {}
    if a.api_base:
        extra["api_base"] = a.api_base
    _key = os.environ.get("SECFORGE_LLM_API_KEY", "").strip()
    if _key:
        extra["api_key"] = _key
    re_effort = (a.reasoning_effort or "").strip()
    effort_kw = _effort_kwargs(a.model, a.effort)   # friendly --effort -> native param

    prompt = _load_prompt(a)
    if not prompt.strip():
        emit({"type": "result", "subtype": "error_no_prompt"})
        print("[litellm-agent] no prompt given", file=sys.stderr)
        sys.exit(2)

    try:
        import litellm  # noqa: E402  (optional dep, imported only for this backend)
    except ImportError:
        emit({"type": "result", "subtype": "error_litellm_missing"})
        print("[litellm-agent] the 'litellm' package is not installed — run "
              "`pip install litellm` to use the litellm backend.", file=sys.stderr)
        sys.exit(2)
    litellm.drop_params = True   # silently ignore params a given provider doesn't accept

    emit({"type": "system", "subtype": "init", "model": a.model,
          "api_base": a.api_base or None})
    print(capability_report(), file=sys.stderr, flush=True)
    emit({"type": "system", "subtype": "capabilities", "mode": _CAPS["mode"],
          "os": _CAPS["os"], "bash": bool(_CAPS["shell_exe"]), "native": _CAPS["native"]})
    messages = [{"role": "system", "content": SYSTEM + "\n\n" + capability_note()},
                {"role": "user", "content": prompt}]

    # Runtime config shared by the root session and any spawned subagents.
    global _LLM, _RUN
    _LLM = litellm
    _RUN = {"model": a.model, "extra": extra, "temperature": a.temperature,
            "max_context_tokens": a.max_context_tokens, "effort_kw": effort_kw,
            "re_effort": re_effort, "sub_turns": max(6, a.subagent_turns)}
    _TOTALS.update(cost=0.0, tin=0, tout=0)
    _SPAWN_BUDGET["left"] = max(0, a.max_subagents)

    def _finish(subtype: str, **extra_fields) -> None:
        emit({"type": "result", "subtype": subtype,
              "total_cost_usd": round(_TOTALS["cost"], 6),
              "usage": {"input_tokens": _TOTALS["tin"], "output_tokens": _TOTALS["tout"]},
              **extra_fields})

    # Depth strategy. 'forced' (default) runs the specialist pipeline
    # deterministically like Claude; 'auto' lets the model delegate via spawn_agent;
    # 'off' is the flat single loop. --max-subagents 0 forces 'off'.
    mode = a.fanout if _SPAWN_BUDGET["left"] > 0 else "off"
    if mode == "forced":
        text, subtype = _forced_fanout(prompt, a.max_turns)
    elif mode == "auto":
        messages[0]["content"] += "\n\n" + _DELEGATION_NOTE
        text, subtype = _agent_loop(messages, TOOLS_SCHEMA_ROOT, a.max_turns, agent=None)
    else:
        text, subtype = _agent_loop(messages, TOOLS_SCHEMA, a.max_turns, agent=None)
    _finish(subtype)
    if subtype == "error_max_turns":
        print(f"[litellm-agent] hit --max-turns ({a.max_turns}) without finishing",
              file=sys.stderr)
        sys.exit(1)
    if subtype.startswith("error"):
        sys.exit(1)


if __name__ == "__main__":
    main()
