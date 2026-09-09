"""Scan runner — executes one scan at a time and folds results into the DB.

A scan launches the existing orchestrator against ONE repo in STATIC mode (no
`--verify`, since the UI runs in Docker without a nested daemon), streams its
output into the scan's log row live, then reads the repo's findings.json and
reconciles it into the global findings table (new vs. still-open vs. mitigated).

Scans are serialized through a single worker thread + queue, so heavy agent
sessions never pile up. `enqueue()` is called by the scheduler (cron) and by the
"Run now" API.
"""
from __future__ import annotations

import dataclasses
import itertools
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import threading
import time
from pathlib import Path

import db
import reportgen

ROOT = Path(__file__).resolve().parent.parent          # security-forge repo root
PY = sys.executable or "python"
DATA_ROOT = db.DATA_ROOT

# Priority queue: report jobs (priority 0) are taken ahead of scans (priority 10),
# so a "Generate report" click jumps the line in front of pending scans. A running
# job is never preempted. `seq` keeps ordering stable within a priority and makes
# every queue item strictly orderable (so PriorityQueue never compares two _Job).
_PRIORITY = {"report": 0, "scan": 10}
_seq = itertools.count()


@dataclasses.dataclass
class _Job:
    kind: str          # 'scan' | 'report'
    repo_id: int | None
    ref_id: int        # scan_id or report_id
    trigger: str


_q: "queue.PriorityQueue[tuple[int, int, _Job]]" = queue.PriorityQueue()
_lock = threading.Lock()
_running: dict[tuple[str, int], int | None] = {}   # (kind, ref_id) -> repo_id
_desired = 1                       # target number of concurrent workers
_live = 0                          # worker threads alive


def _submit(job: _Job) -> None:
    _q.put((_PRIORITY.get(job.kind, 50), next(_seq), job))


def enqueue(repo_id: int, trigger: str = "manual") -> int:
    """Queue a scan for a repo. Returns the scan id (created immediately as queued)."""
    repo = db.get_repo(repo_id)
    if not repo:
        raise ValueError("no such repo")
    scan_id = db.create_scan(repo_id, repo["slug"], trigger)
    _submit(_Job("scan", repo_id, scan_id, trigger))
    return scan_id


def enqueue_report(repo_id: int | None, trigger: str = "manual") -> dict:
    """Queue an executive report — repo_id=None means a portfolio (all-repos)
    report. Priority over scans. Returns the created report row's {id, uuid}."""
    if repo_id is not None:
        repo = db.get_repo(repo_id)
        if not repo:
            raise ValueError("no such repo")
        slug, scope = repo["slug"], repo["slug"]
        title = f"Security Report — {repo.get('name') or slug}"
    else:
        slug, scope, title = "", "all repositories", "Portfolio Security Report"
    report_id, uuid = db.create_report(repo_id, slug, scope, title, trigger)
    _submit(_Job("report", repo_id, report_id, trigger))
    return {"id": report_id, "uuid": uuid}


def status() -> dict:
    with _lock:
        scans = [ref for (kind, ref) in _running if kind == "scan"]
        reports_running = [ref for (kind, ref) in _running if kind == "report"]
    return {"running": scans, "running_count": len(scans),
            "reports_running": reports_running,
            "reports_running_count": len(reports_running),
            "queued": _q.qsize(), "max": _desired}


def _findings_path(slug: str) -> Path:
    return DATA_ROOT / "knowledge" / slug / "findings.json"


# Engine store statuses that mean "no longer an active finding": the analysis itself
# retired it — `dismissed` = judged non-applicable (e.g. the agent honored an operator
# comment / false-positive), `fixed` = remediated. Excluding these here makes the UI
# reconcile mitigate them instead of keeping them open, so "orca" marking a finding
# non-applicable actually removes it from the open list (it no longer resurfaces).
_RESOLVED_ENGINE_STATUS = {"dismissed", "fixed"}


def _load_findings(slug: str) -> list[dict]:
    p = _findings_path(slug)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    rows = list(data.values()) if isinstance(data, dict) else []
    return [f for f in rows
            if (f.get("status") or "").lower() not in _RESOLVED_ENGINE_STATUS]


def _resolved_status_map(slug: str) -> dict[str, str]:
    """{engine finding id -> 'dismissed'|'fixed'} for findings the analysis retired —
    so reconcile can mitigate them with an accurate reason (not the generic
    'not rediscovered')."""
    p = _findings_path(slug)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    rows = list(data.values()) if isinstance(data, dict) else []
    return {f["id"]: (f.get("status") or "").lower() for f in rows
            if f.get("id") and (f.get("status") or "").lower() in _RESOLVED_ENGINE_STATUS}


def _load_model(slug: str) -> dict | None:
    p = DATA_ROOT / "knowledge" / slug / "model.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_scan(repo_id: int, scan_id: int) -> None:
    repo = db.get_repo(repo_id)
    if not repo:
        db.update_scan(scan_id, status="error", error="repo deleted", finished=db._now())
        return
    slug = repo["slug"]
    db.update_scan(scan_id, status="running", started=db._now())
    db.upsert_repo({"url": repo["url"]}, repo_id)  # touch updated
    with db.connect() as c:
        c.execute("UPDATE repos SET last_scan_id=?, last_status='running' WHERE id=?",
                  (scan_id, repo_id))

    # The AI is ONE global template applied to every scan (backend/model/keys/args).
    # A repository only contributes WHAT to scan and its per-repo context.
    cfg = db.get_setting("defaults", {}) or {}
    # NOT --silent: the UI streams the orchestrator's live progress (turns, tools,
    # heartbeats) into the scan log so the operator can watch it in real time. A
    # 10s heartbeat (vs the 30s default) makes that stream feel live.
    cmd = [PY, str(ROOT / "orchestrate.py"), "--repo", repo["url"],
           "--backend", cfg.get("backend") or "litellm",
           "--output-dir", str(DATA_ROOT), "--heartbeat", "10"]
    for flag, key in [("--model", "model"), ("--agent-base-url", "base_url"),
                      ("--agent-max-turns", "max_turns"),
                      ("--agent-temperature", "temperature"), ("--timeout", "timeout"),
                      ("--agent-cmd", "agent_cmd"), ("--agent-output", "agent_output")]:
        val = cfg.get(key)
        if val not in (None, ""):
            cmd += [flag, str(val)]
    if cfg.get("extra_args"):
        try:
            extra = shlex.split(cfg["extra_args"])
        except ValueError:
            extra = str(cfg["extra_args"]).split()
        # The UI container has no nested Docker daemon, so verification is impossible
        # here — strip --verify / bare 'nuke'. UI scans are static.
        cmd += [a for a in extra if a not in ("--verify", "nuke")]

    env = {**os.environ, "SECFORGE_DATA_DIR": str(DATA_ROOT)}
    # Per-repo context + the operator's prior triage decisions are both injected as
    # SECFORGE_EXTRA_CONTEXT (the orchestrator folds it into the scan prompt as
    # authoritative user context) so the agent triages consistently and stops
    # re-reporting findings a human already dismissed as false positives.
    # Assemble the authoritative operator context, broadest scope first: enabled
    # skills (global) -> project instructions (group) -> repo context (one) ->
    # triage decisions + comments (per finding). All are handed to the agent via
    # SECFORGE_EXTRA_CONTEXT and echoed into the scan log below so it's auditable.
    ctx_parts = []
    skills = db.enabled_skills_text()          # operator-uploaded .md playbooks
    if skills:
        ctx_parts.append(skills)
    proj = db.project_instructions(repo_id)    # shared instructions from the repo's project
    if proj:
        ctx_parts.append(proj)
    smap = db.project_service_map(repo_id)     # sibling services' cards (shared knowledge, not code)
    if smap:
        ctx_parts.append(smap)
    if (repo.get("context") or "").strip():
        ctx_parts.append(repo["context"].strip())
    triage_ctx = db.triage_context(repo_id)    # prior triage + operator comments
    if triage_ctx:
        ctx_parts.append(triage_ctx)
    if ctx_parts:
        env["SECFORGE_EXTRA_CONTEXT"] = "\n\n".join(ctx_parts)
    # Global AI env (provider keys, base URLs, SECFORGE_LLM_API_KEY, …) for every scan.
    _ctx_dbg = env.get("SECFORGE_EXTRA_CONTEXT", "")
    try:
        for e in (cfg.get("env") or []):
            k = (e.get("key") or "").strip()
            if k:
                env[k] = str(e.get("value", ""))
    except (AttributeError, TypeError):
        pass

    db.append_scan_log(scan_id, f"$ {' '.join(shlex.quote(x) for x in cmd)}\n\n")
    # Audit trail: record EXACTLY what operator context was handed to the agent, so
    # you can confirm skills / project / repo context / triage + comments went in.
    if _ctx_dbg:
        db.append_scan_log(scan_id, "===== operator context injected into this scan "
                           "(skills -> project -> repo context -> triage & comments) "
                           "=====\n" + _ctx_dbg + "\n===== end operator context =====\n\n")
    else:
        db.append_scan_log(scan_id, "[runner] NOTE: no operator context for this scan "
                           "(no enabled skills, no project instructions, no repo "
                           "context, no prior triage/comments).\n\n")
    db.update_scan(scan_id, heartbeat=db._now())
    commit = None
    orch_error: str | None = None   # a repo-level failure the orchestrator printed
    cost = 0.0                      # $ spent, parsed from the orchestrator summary line
    buf: list[str] = []
    last_flush = 0.0

    def _flush() -> None:
        nonlocal last_flush
        if buf:
            db.append_scan_log(scan_id, "".join(buf)); buf.clear()
        db.update_scan(scan_id, heartbeat=db._now())   # heartbeat = last live output
        last_flush = time.monotonic()

    try:
        p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                             errors="replace", env=env, bufsize=1)
        for line in iter(p.stdout.readline, ""):
            buf.append(line)
            m = re.search(r"prepped @ ([0-9a-fA-F]{6,40})", line)
            if m:
                commit = m.group(1)
            # The orchestrator can fail a repo while still exiting 0 (e.g. clone/prep
            # failed → "✗ prep failed: …" and a final "<slug> -> error"). Capture that
            # so the scan is marked ERROR, not a silent empty success.
            if "prep failed:" in line:
                orch_error = line.split("prep failed:", 1)[1].strip().rstrip("\n")
            elif re.search(r"->\s*error\b", line) and orch_error is None:
                orch_error = "orchestrator reported an error for this repository"
            mc = re.search(r"cost=\$([0-9]+(?:\.[0-9]+)?)", line)
            if mc:
                cost = float(mc.group(1))
            # Near-real-time: flush on a small batch OR every ~0.4s, whichever first.
            if len(buf) >= 4 or (time.monotonic() - last_flush) >= 0.4:
                _flush()
        p.wait()
        _flush()
        rc = p.returncode
    except Exception as e:  # noqa: BLE001
        db.append_scan_log(scan_id, f"\n[runner] error: {e}\n")
        db.update_scan(scan_id, status="error", error=str(e)[:500], finished=db._now())
        _finalize_repo(repo_id, scan_id, "error", None)
        return

    # ERROR path — orchestrator crashed (rc!=0) or flagged the repo as failed. Do NOT
    # reconcile findings here: an empty/stale findings.json would falsely "mitigate"
    # every previously-open finding. Leave prior findings exactly as they were.
    if rc != 0 or orch_error:
        err = orch_error or f"orchestrator exit {rc}"
        db.update_scan(scan_id, status="error", finished=db._now(), commit_sha=commit,
                       cost_usd=cost, error=err[:500])
        db.append_scan_log(scan_id, f"\n[runner] scan ended with ERROR (rc={rc}): {err}\n")
        _finalize_repo(repo_id, scan_id, "error", commit)
        return

    findings = _load_findings(slug)
    stats = db.reconcile_findings(repo_id, slug, scan_id, findings, commit,
                                  resolved=_resolved_status_map(slug))
    # Harvest this repo's SERVICE CARD (exposes / auth / outbound calls) from its
    # recon model into the project's shared knowledge — so sibling scans can validate
    # against what this service declares, without ever cloning its code.
    _model = _load_model(slug)
    if _model:
        try:
            db.upsert_service_card(repo_id, slug, db.build_card_from_model(_model))
        except Exception:  # noqa: BLE001  (card harvest must never fail a scan)
            pass
    db.update_scan(scan_id, status="done", finished=db._now(), commit_sha=commit,
                   new_count=stats["new"], mitigated_count=stats["mitigated"],
                   total_count=stats["total"], cost_usd=cost, error=None)
    db.append_scan_log(scan_id, f"\n[runner] done rc={rc}: {stats['new']} new, "
                       f"{stats['mitigated']} mitigated, {stats['total']} open"
                       f"{f' · ${cost:.2f} spent' if cost else ''}.\n")
    _finalize_repo(repo_id, scan_id, "done", commit)


def _finalize_repo(repo_id: int, scan_id: int, st: str, commit: str | None) -> None:
    with db.connect() as c:
        c.execute("UPDATE repos SET last_scan_id=?, last_status=?, last_scanned=? WHERE id=?",
                  (scan_id, st, db._now(), repo_id))


def _run_report(report_id: int) -> None:
    reportgen.run_report(report_id)


def _worker() -> None:
    global _live
    while True:
        # scale down: if the pool shrank, retire this worker
        with _lock:
            if _live > _desired:
                _live -= 1
                return
        try:
            _prio, _n, job = _q.get(timeout=1.0)
        except queue.Empty:
            continue
        key = (job.kind, job.ref_id)
        with _lock:
            _running[key] = job.repo_id
        try:
            if job.kind == "report":
                _run_report(job.ref_id)
            else:
                _run_scan(job.repo_id, job.ref_id)
        except Exception as e:  # noqa: BLE001  (never let the worker die)
            try:
                if job.kind == "report":
                    db.update_report(job.ref_id, status="error",
                                     error=str(e)[:500], finished=db._now())
                else:
                    db.update_scan(job.ref_id, status="error", error=str(e)[:500],
                                   finished=db._now())
                    _finalize_repo(job.repo_id, job.ref_id, "error", None)
            except Exception:
                pass
        finally:
            with _lock:
                _running.pop(key, None)
            _q.task_done()


def set_concurrency(n: int) -> int:
    """Set how many orchestrators run at once (>=1). Grows the pool immediately;
    shrinking takes effect as busy workers finish. Returns the new target."""
    global _desired, _live
    n = max(1, int(n or 1))
    with _lock:
        _desired = n
        to_add = max(0, n - _live)
        _live += to_add
    for _ in range(to_add):
        threading.Thread(target=_worker, name="scan-worker", daemon=True).start()
    return _desired


def start_worker(n: int = 1) -> None:
    set_concurrency(n)
