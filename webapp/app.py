"""security-forge UI — FastAPI backend.

A control plane for continuous scanning: manage repos + their cron schedules +
per-repo context/args, run and monitor scans, and browse a global findings table
rendered in the advisory format (with PDF export + executive report). Login is
root/root on first boot; the password must be changed after first login. Static
analysis only (no verification) — all data lives in the DB.
"""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import shutil
import sqlite3
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

import db
import reports
import runner
import scheduler

STATIC = Path(__file__).resolve().parent / "static"

db.init()
# Prefer an explicit secret from the environment (stable across restarts/replicas),
# else a persisted per-install one, else generate + persist.
_secret = (os.environ.get("SECFORGE_UI_SECRET") or "").strip() or db.get_setting("session_secret")
if not _secret:
    _secret = secrets.token_hex(32)
    db.set_setting("session_secret", _secret)

app = FastAPI(title="security-forge UI", docs_url=None, redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=_secret, https_only=False,
                   same_site="lax", max_age=60 * 60 * 12)


# Sensible defaults for the global AI config. timeout "0" = NO limit (let a scan
# run to completion) — the default the user asked for.
DEFAULT_DEFAULTS = {"backend": "litellm", "model": "", "base_url": "", "max_turns": "",
                    "temperature": "", "timeout": "0", "agent_cmd": "", "agent_output": "",
                    "extra_args": "", "env": [], "effort": "max",
                    "fanout": "forced", "max_subagents": 6, "subagent_turns": 40}


@app.on_event("startup")
def _startup() -> None:
    # HOME lives on the /data volume so agent-CLI logins persist across restarts.
    try:
        os.makedirs(os.environ.get("HOME", "/data/home"), exist_ok=True)
    except OSError:
        pass
    # Seed the global AI config on first boot (no-timeout default), so scans run
    # unbounded until the operator changes it.
    if db.get_setting("defaults") is None:
        db.set_setting("defaults", DEFAULT_DEFAULTS)
    runner.start_worker(int(db.get_setting("max_concurrent_scans", 1) or 1))
    scheduler.start()


# --- auth -------------------------------------------------------------------

def require_user(request: Request) -> str:
    u = request.session.get("user")
    if not u:
        raise HTTPException(status_code=401, detail="login required")
    return u


@app.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = db.verify_user(username, password)
    if not user:
        raise HTTPException(status_code=401, detail="invalid credentials")
    request.session["user"] = username
    return {"ok": True, "username": username, "must_change": bool(user.get("must_change"))}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def me(request: Request, user: str = Depends(require_user)):
    u = db.get_user(user) or {}
    return {"username": user, "must_change": bool(u.get("must_change"))}


@app.post("/api/change-password")
async def change_password(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    if not db.verify_user(user, body.get("current", "")):
        raise HTTPException(status_code=400, detail="current password is wrong")
    new = (body.get("new") or "").strip()
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="new password too short (min 4)")
    db.set_password(user, new)
    return {"ok": True}


# --- backends / settings ----------------------------------------------------

def _authed(subdir: str) -> bool:
    d = Path(os.environ.get("HOME", "/data/home")) / subdir
    try:
        return d.is_dir() and any(d.iterdir())
    except OSError:
        return False


def _available_backends() -> list[dict]:
    # CLI backends: available if the binary is installed; "authorized" if their
    # config dir under $HOME (the /data volume) exists — log in via `docker exec`.
    out = [{"name": "litellm", "kind": "native (no CLI)",
            "available": importlib.util.find_spec("litellm") is not None, "authorized": None,
            "authorize": "no login — provide a provider key (repo env / OPENAI_API_KEY, "
                         "ANTHROPIC_API_KEY, or SECFORGE_LLM_API_KEY)",
            "hint": "model e.g. openai/gpt-5, anthropic/claude-3-7-sonnet, ollama/llama3"}]
    for name, binary, cfg, cmd, hint in [
        ("claude-code", "claude", ".claude", "claude", "or set ANTHROPIC_API_KEY"),
        ("codex", "codex", ".codex", "codex login", "or set OPENAI_API_KEY"),
        ("gemini", "gemini", ".gemini", "gemini", "or set GEMINI_API_KEY"),
        ("aider", "aider", ".aider", "", "uses provider API keys (env)"),
    ]:
        avail = shutil.which(binary) is not None
        out.append({"name": name, "kind": "CLI", "available": avail,
                    "authorized": _authed(cfg) if avail else False,
                    "authorize": (f"docker exec -it <container> {cmd}   ({hint})"
                                  if cmd else hint),
                    "hint": hint})
    return out


@app.get("/api/backends")
def backends(user: str = Depends(require_user)):
    return {"backends": _available_backends(),
            "home": os.environ.get("HOME", "/data/home")}


# Fixed, whitelisted login commands — the PTY endpoint runs ONLY these.
_AUTH_CMDS = {"claude-code": ["claude"], "codex": ["codex", "login"], "gemini": ["gemini"]}


@app.websocket("/ws/auth")
async def ws_auth(ws: WebSocket):
    """Interactive login for a CLI backend, in the browser. Bridges an xterm.js
    terminal to a PTY running ONLY a whitelisted login command inside the
    container; the credentials it writes land under $HOME (the /data volume) and
    persist. Session-gated. POSIX only (the container is Linux)."""
    import asyncio
    await ws.accept()
    if not ws.session.get("user"):
        await ws.send_text("not authorized\r\n"); await ws.close(); return
    argv = _AUTH_CMDS.get(ws.query_params.get("backend", ""))
    if not argv or not shutil.which(argv[0]):
        await ws.send_text("backend not available\r\n"); await ws.close(); return
    try:
        import fcntl, pty, struct, termios  # noqa: E401  (POSIX-only, lazy)
        import subprocess
        master, slave = pty.openpty()
        proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                start_new_session=True, env={**os.environ})
        os.close(slave)
    except Exception as e:  # noqa: BLE001
        await ws.send_text(f"failed to start: {e}\r\n"); await ws.close(); return

    loop = asyncio.get_event_loop()
    await ws.send_text(f"$ {' '.join(argv)}\r\n")

    async def pump_out():
        while True:
            data = await loop.run_in_executor(None, lambda: os.read(master, 4096))
            if not data:
                break
            await ws.send_text(data.decode("utf-8", "replace"))

    async def pump_in():
        while True:
            msg = await ws.receive_text()
            if msg.startswith("\x00resize:"):
                try:
                    cols, rows = (int(x) for x in msg[8:].split(","))
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                except (ValueError, OSError):
                    pass
            else:
                os.write(master, msg.encode("utf-8"))

    tasks = [asyncio.create_task(pump_out()), asyncio.create_task(pump_in())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except Exception:  # noqa: BLE001
        pass
    for t in tasks:
        t.cancel()
    for fn in (lambda: proc.terminate(), lambda: os.close(master)):
        try:
            fn()
        except Exception:
            pass
    try:
        await ws.send_text("\r\n[session ended — reopen Backends to refresh status]\r\n")
        await ws.close()
    except Exception:
        pass


@app.get("/api/settings")
def get_settings(user: str = Depends(require_user)):
    return {"defaults": db.get_setting("defaults", DEFAULT_DEFAULTS),
            "max_concurrent_scans": int(db.get_setting("max_concurrent_scans", 1) or 1),
            "schema": db.schema_info()}


@app.put("/api/settings")
async def put_settings(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    if isinstance(body.get("defaults"), dict):
        db.set_setting("defaults", {**DEFAULT_DEFAULTS, **body["defaults"]})
    n = None
    if body.get("max_concurrent_scans") is not None:
        n = runner.set_concurrency(body.get("max_concurrent_scans"))
        db.set_setting("max_concurrent_scans", n)
    return {"ok": True, "max_concurrent_scans": n}


# --- skills (operator .md playbooks injected into every scan) ---------------

@app.get("/api/skills")
def skills(user: str = Depends(require_user)):
    return {"skills": db.list_skills()}


@app.get("/api/skills/{sid}")
def skill_detail(sid: int, user: str = Depends(require_user)):
    s = db.get_skill(sid)
    if not s:
        raise HTTPException(404, "no such skill")
    return s


@app.post("/api/skills")
async def create_skill(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    if not (body.get("name") or "").strip():
        raise HTTPException(400, "name required")
    return {"ok": True, "id": db.upsert_skill(body)}


@app.put("/api/skills/{sid}")
async def update_skill(sid: int, request: Request, user: str = Depends(require_user)):
    if not db.get_skill(sid):
        raise HTTPException(404, "no such skill")
    db.upsert_skill(await request.json(), sid)
    return {"ok": True}


@app.delete("/api/skills/{sid}")
def remove_skill(sid: int, user: str = Depends(require_user)):
    db.delete_skill(sid)
    return {"ok": True}


# --- projects (a group of repos sharing inherited ground-truth instructions) ------

@app.get("/api/projects")
def projects(user: str = Depends(require_user)):
    return {"projects": db.list_projects()}


@app.get("/api/projects/{pid}")
def project_detail(pid: int, user: str = Depends(require_user)):
    p = db.get_project(pid)
    if not p:
        raise HTTPException(404, "no such project")
    return p


@app.post("/api/projects")
async def create_project(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    if not (body.get("name") or "").strip():
        raise HTTPException(400, "name required")
    return {"ok": True, "id": db.upsert_project(body)}


@app.put("/api/projects/{pid}")
async def update_project(pid: int, request: Request, user: str = Depends(require_user)):
    if not db.get_project(pid):
        raise HTTPException(404, "no such project")
    db.upsert_project(await request.json(), pid)
    return {"ok": True}


@app.delete("/api/projects/{pid}")
def remove_project(pid: int, user: str = Depends(require_user)):
    db.delete_project(pid)
    return {"ok": True}


# --- repos ------------------------------------------------------------------

@app.get("/api/repos")
def repos(user: str = Depends(require_user)):
    nxt = scheduler.next_runs()
    out = []
    for r in db.list_repos():
        openf = db.list_findings(status="open", repo_id=r["id"])
        sev = {}
        for f in openf:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        r = dict(r)
        r["open_findings"] = len(openf)
        r["by_severity"] = sev
        r["next_run"] = nxt.get(f"repo-{r['id']}")
        out.append(r)
    return {"repos": out, "runner": runner.status()}


@app.get("/api/repos/{rid}")
def repo_detail(rid: int, user: str = Depends(require_user)):
    r = db.get_repo(rid)
    if not r:
        raise HTTPException(404, "no such repo")
    return {"repo": r, "findings": db.list_findings(repo_id=rid),
            "scans": db.list_scans(repo_id=rid, limit=50),
            "next_run": scheduler.next_runs().get(f"repo-{rid}")}


@app.post("/api/repos")
async def create_repo(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    if not (body.get("url") or "").strip():
        raise HTTPException(400, "Enter a Git URL.")
    if db.repo_by_url(body["url"]):
        raise HTTPException(409, "This repository is already added — open it from the Repositories list.")
    try:
        rid = db.upsert_repo(body)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "This repository is already added.")
    scheduler.reload()
    return {"ok": True, "id": rid}


@app.put("/api/repos/{rid}")
async def update_repo(rid: int, request: Request, user: str = Depends(require_user)):
    if not db.get_repo(rid):
        raise HTTPException(404, "no such repo")
    body = await request.json()
    other = db.repo_by_url(body.get("url") or "")
    if other and other["id"] != rid:
        raise HTTPException(409, "Another repository already uses that URL.")
    try:
        db.upsert_repo(body, rid)
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Another repository already uses that URL.")
    scheduler.reload()
    return {"ok": True}


@app.delete("/api/repos/{rid}")
def remove_repo(rid: int, user: str = Depends(require_user)):
    db.delete_repo(rid)
    scheduler.reload()
    return {"ok": True}


# Per-scan effort levels the Scan dialog's slider can request (maps per model in the
# litellm agent). Anything else is ignored so a scan falls back to the global default.
_EFFORT_LEVELS = {"low", "medium", "high", "max", "normal", "off"}


def _clean_effort(effort: str | None) -> str | None:
    e = (effort or "").strip().lower()
    return e if e in _EFFORT_LEVELS else None


@app.post("/api/repos/{rid}/scan")
def scan_now(rid: int, effort: str | None = None, user: str = Depends(require_user)):
    if not db.get_repo(rid):
        raise HTTPException(404, "no such repo")
    try:
        return {"ok": True, "scan_id": runner.enqueue(rid, "manual", _clean_effort(effort))}
    except runner.AlreadyQueued as e:
        raise HTTPException(409, "a scan is already queued or running for this repository")


# --- scans ------------------------------------------------------------------

@app.get("/api/scans")
def scans(repo_id: int | None = None, user: str = Depends(require_user)):
    return {"scans": db.list_scans(repo_id=repo_id), "runner": runner.status()}


@app.get("/api/scans/{sid}")
def scan_detail(sid: int, user: str = Depends(require_user)):
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "no such scan")
    s["findings"] = db.list_findings_by_scan(sid)
    return s


@app.post("/api/scans/{sid}/relaunch")
def relaunch_scan(sid: int, effort: str | None = None, user: str = Depends(require_user)):
    """Re-run the same repository as a fresh scan (a new run record)."""
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "no such scan")
    if not db.get_repo(s["repo_id"]):
        raise HTTPException(404, "repository was deleted")
    try:
        return {"ok": True, "scan_id": runner.enqueue(s["repo_id"], "relaunch", _clean_effort(effort))}
    except runner.AlreadyQueued as e:
        raise HTTPException(409, "a scan is already queued or running for this repository")


@app.delete("/api/scans/{sid}")
def delete_scan(sid: int, user: str = Depends(require_user)):
    """Delete a finished scan run (its log + counters). Findings are untouched."""
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "no such scan")
    if s["status"] in ("queued", "running"):
        raise HTTPException(409, "cannot delete a scan that is queued or running")
    db.delete_scan(sid)
    return {"ok": True}


# --- findings ---------------------------------------------------------------

@app.get("/api/findings")
def findings(status: str | None = None, repo_id: int | None = None,
             min_sev: str | None = None, user: str = Depends(require_user)):
    return {"findings": db.list_findings(status=status, repo_id=repo_id, min_sev=min_sev),
            "counts": db.counts()}


@app.get("/api/findings/{fid}")
def finding_detail(fid: str, user: str = Depends(require_user)):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "no such finding")
    md = reports.advisory_markdown(f)
    return {"finding": f, "advisory_markdown": md,
            "advisory_html": reports.markdown_fragment(md),
            "comments": db.list_comments(f["uuid"]),
            "review_hints": db.review_hints(f),
            "triage_values": db.TRIAGE_VALUES, "triage_labels": db.TRIAGE_LABEL}


@app.put("/api/findings/{fid}/triage")
async def set_finding_triage(fid: str, request: Request, user: str = Depends(require_user)):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "no such finding")
    body = await request.json()
    try:
        status = db.set_triage(f["uuid"], (body.get("triage") or "unset"),
                               body.get("note") or "", user)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "status": status}


@app.post("/api/findings/{fid}/comments")
async def add_finding_comment(fid: str, request: Request, user: str = Depends(require_user)):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "no such finding")
    body = await request.json()
    try:
        c = db.add_comment(f["uuid"], user, body.get("body") or "")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True, "comment": c}


@app.get("/api/findings/{fid}/advisory.pdf")
def finding_pdf(fid: str, user: str = Depends(require_user)):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "no such finding")
    pdf = reports.to_pdf(reports.advisory_html(f))
    name = (f.get("fid") or fid).replace("/", "_")
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="advisory-{name}.pdf"'})


@app.get("/api/report")
def exec_report(repo_id: int | None = None, user: str = Depends(require_user)):
    return {"markdown": reports.executive_markdown(repo_id)}


@app.get("/api/report.pdf")
def exec_report_pdf(repo_id: int | None = None, user: str = Depends(require_user)):
    pdf = reports.to_pdf(reports.executive_html(repo_id))
    tag = f"repo-{repo_id}" if repo_id else "all"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="exec-{tag}.pdf"'})


# --- reports (AI-written, JET-format, priority-queued, downloadable) --------

@app.post("/api/reports/generate")
def generate_report(repo_id: int | None = None, user: str = Depends(require_user)):
    """Queue an executive report. repo_id omitted = portfolio (all repos). The
    report job takes priority over pending scans."""
    if repo_id is not None and not db.get_repo(repo_id):
        raise HTTPException(404, "no such repo")
    return {"ok": True, "report": runner.enqueue_report(repo_id, "manual")}


@app.post("/api/repos/{rid}/report")
def generate_repo_report(rid: int, user: str = Depends(require_user)):
    if not db.get_repo(rid):
        raise HTTPException(404, "no such repo")
    return {"ok": True, "report": runner.enqueue_report(rid, "manual")}


@app.get("/api/reports")
def list_reports(repo_id: int | None = None, user: str = Depends(require_user)):
    return {"reports": db.list_reports(repo_id=repo_id), "runner": runner.status()}


def _report_ready(uuid: str) -> dict:
    r = db.get_report_by_uuid(uuid)
    if not r:
        raise HTTPException(404, "no such report")
    if r["status"] != "done" or not (r.get("markdown") or "").strip():
        raise HTTPException(409, f"report is not ready (status: {r['status']})")
    return r


# NOTE: the .pdf / .md download routes MUST be declared before the bare
# /api/reports/{uuid} detail route — a str path param matches dots too, so the
# bare route would otherwise capture "<uuid>.pdf" as the uuid.
@app.get("/api/reports/{uuid}.md")
def report_md(uuid: str, user: str = Depends(require_user)):
    r = _report_ready(uuid)
    name = (r.get("slug") or "portfolio").replace("/", "_")
    return Response(r["markdown"], media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="report-{name}-{uuid}.md"'})


@app.get("/api/reports/{uuid}.pdf")
def report_pdf(uuid: str, user: str = Depends(require_user)):
    r = _report_ready(uuid)
    name = (r.get("slug") or "portfolio").replace("/", "_")
    pdf = reports.report_pdf(r)
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="report-{name}-{uuid}.pdf"'})


@app.get("/api/reports/{uuid}")
def report_detail(uuid: str, user: str = Depends(require_user)):
    r = db.get_report_by_uuid(uuid)
    if not r:
        raise HTTPException(404, "no such report")
    return {"report": r, "html": reports.markdown_fragment(r.get("markdown") or "")}


@app.delete("/api/reports/{uuid}")
def remove_report(uuid: str, user: str = Depends(require_user)):
    r = db.get_report_by_uuid(uuid)
    if not r:
        raise HTTPException(404, "no such report")
    if r["status"] in ("queued", "running"):
        raise HTTPException(409, "cannot delete a report that is queued or running")
    db.delete_report(r["id"])
    return {"ok": True}


# --- artifacts (observe what the orchestrator wrote on disk) ----------------
# The orchestrator ("orca") writes the durable "map" of every scan under the data
# root: knowledge/<slug>/ (model.json + the PROJECT/AUTH/ROLES/ENTRYPOINTS/
# TRUST_BOUNDARIES.md recon docs + findings.json + notifications.log), reports/
# (per-repo .md + advisories + INDEX), logs/orch-*.log (full run logs), findings/,
# state/. None of that is in the DB, so this read-only browser surfaces the tree so
# an operator can observe and debug exactly what a scan did. Session-gated; path is
# resolved under the data root with traversal refused and only these folders exposed
# (never db/ or the $HOME CLI-credential dirs on the same volume).
_ART_ROOT = db.DATA_ROOT.resolve()
_ART_TOP = ("knowledge", "reports", "findings", "logs", "state")
_ART_TEXT_MAX = 2_000_000           # bytes rendered inline; larger -> download only
_ART_MD = {".md", ".markdown"}
_ART_JSON = {".json"}
_ART_TEXT = {".log", ".txt", ".text", ".yaml", ".yml", ".csv", ".ini", ".cfg", ".toml",
             ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh", ".sql",
             ".html", ".css", ".xml", ".env", ".dockerfile", ""}


def _art_kind(p: Path) -> str:
    ext = p.suffix.lower()
    if ext in _ART_MD:
        return "md"
    if ext in _ART_JSON:
        return "json"
    if ext in _ART_TEXT or p.name.lower() in ("dockerfile", "makefile", "readme"):
        return "text"
    return "binary"


def _art_resolve(rel: str) -> Path:
    """Resolve a caller-supplied relative path under the data root, refusing escape.
    '' is the root. Any path whose first segment isn't a whitelisted artifact folder
    (or that resolves outside the root) is rejected."""
    rel = (rel or "").strip().replace("\\", "/").lstrip("/")
    p = (_ART_ROOT / rel).resolve()
    if p != _ART_ROOT and _ART_ROOT not in p.parents:
        raise HTTPException(400, "path escapes the data root")
    if p != _ART_ROOT and p.relative_to(_ART_ROOT).parts[0] not in _ART_TOP:
        raise HTTPException(404, "not a browsable artifact folder")
    return p


@app.get("/api/artifacts")
def artifacts_list(path: str = "", user: str = Depends(require_user)):
    """Directory listing under the data root. The root lists only the artifact
    folders that actually exist; any deeper folder lists its real contents."""
    p = _art_resolve(path)
    if not p.is_dir():
        raise HTTPException(404, "no such folder")
    rel = "" if p == _ART_ROOT else p.relative_to(_ART_ROOT).as_posix()
    try:
        kids = sorted(p.iterdir(), key=lambda c: (c.is_file(), c.name.lower()))
    except OSError:
        kids = []
    entries = []
    for c in kids:
        if p == _ART_ROOT and c.name not in _ART_TOP:
            continue                # hide db/, home/, etc. at the root
        try:
            st = c.stat()
        except OSError:
            continue
        entries.append({"name": c.name, "path": c.relative_to(_ART_ROOT).as_posix(),
                        "is_dir": c.is_dir(), "size": st.st_size,
                        "mtime": int(st.st_mtime),
                        "kind": "dir" if c.is_dir() else _art_kind(c)})
    return {"path": rel, "entries": entries}


@app.get("/api/artifacts/view")
def artifacts_view(path: str, user: str = Depends(require_user)):
    """One file's content for inline display: markdown rendered to HTML, JSON
    pretty-printed, text as-is. Binary or oversized files are flagged download-only."""
    p = _art_resolve(path)
    if not p.is_file():
        raise HTTPException(404, "no such file")
    st = p.stat()
    kind = _art_kind(p)
    out = {"path": p.relative_to(_ART_ROOT).as_posix(), "name": p.name,
           "size": st.st_size, "mtime": int(st.st_mtime), "kind": kind}
    if kind == "binary" or st.st_size > _ART_TEXT_MAX:
        out["download_only"] = True
        out["too_large"] = st.st_size > _ART_TEXT_MAX
        return out
    raw = p.read_text(encoding="utf-8", errors="replace")
    if kind == "json":
        try:
            raw = json.dumps(json.loads(raw), indent=2, ensure_ascii=False)
        except ValueError:
            pass                    # not valid JSON — show the bytes as they are
    out["raw"] = raw
    if kind == "md":
        out["html"] = reports.markdown_fragment(raw)
    return out


@app.get("/api/artifacts/raw")
def artifacts_raw(path: str, user: str = Depends(require_user)):
    """The raw file. Text-like files (md/json/log/…) are served inline as plain
    text so "Raw ↗" opens them in the browser; binaries download."""
    p = _art_resolve(path)
    if not p.is_file():
        raise HTTPException(404, "no such file")
    if _art_kind(p) == "binary":
        return FileResponse(str(p), filename=p.name)        # attachment → download
    return FileResponse(str(p), media_type="text/plain; charset=utf-8")   # inline view


# --- static SPA -------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.exception_handler(401)
async def _401(request: Request, exc: HTTPException):
    return JSONResponse({"detail": "login required"}, status_code=401)
