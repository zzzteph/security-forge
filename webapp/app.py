"""security-forge UI — FastAPI backend.

A control plane for continuous scanning: manage repos + their cron schedules +
per-repo context/args, run and monitor scans, and browse a global findings table
rendered in the advisory format (with PDF export + executive report). Login is
root/root on first boot; the password must be changed after first login. Static
analysis only (no verification) — all data lives in the DB.
"""
from __future__ import annotations

import importlib.util
import os
import secrets
import shutil
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
                    "extra_args": "", "env": []}


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
            "max_concurrent_scans": int(db.get_setting("max_concurrent_scans", 1) or 1)}


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
        raise HTTPException(400, "url required")
    rid = db.upsert_repo(body)
    scheduler.reload()
    return {"ok": True, "id": rid}


@app.put("/api/repos/{rid}")
async def update_repo(rid: int, request: Request, user: str = Depends(require_user)):
    if not db.get_repo(rid):
        raise HTTPException(404, "no such repo")
    body = await request.json()
    db.upsert_repo(body, rid)
    scheduler.reload()
    return {"ok": True}


@app.delete("/api/repos/{rid}")
def remove_repo(rid: int, user: str = Depends(require_user)):
    db.delete_repo(rid)
    scheduler.reload()
    return {"ok": True}


@app.post("/api/repos/{rid}/scan")
def scan_now(rid: int, user: str = Depends(require_user)):
    if not db.get_repo(rid):
        raise HTTPException(404, "no such repo")
    return {"ok": True, "scan_id": runner.enqueue(rid, "manual")}


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
def relaunch_scan(sid: int, user: str = Depends(require_user)):
    """Re-run the same repository as a fresh scan (a new run record)."""
    s = db.get_scan(sid)
    if not s:
        raise HTTPException(404, "no such scan")
    if not db.get_repo(s["repo_id"]):
        raise HTTPException(404, "repository was deleted")
    return {"ok": True, "scan_id": runner.enqueue(s["repo_id"], "relaunch")}


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
    return {"finding": f, "advisory_markdown": reports.advisory_markdown(f),
            "comments": db.list_comments(f["uuid"]),
            "triage_values": db.TRIAGE_VALUES, "triage_labels": db.TRIAGE_LABEL}


@app.put("/api/findings/{fid}/triage")
async def set_finding_triage(fid: str, request: Request, user: str = Depends(require_user)):
    f = db.get_finding(fid)
    if not f:
        raise HTTPException(404, "no such finding")
    body = await request.json()
    try:
        db.set_triage(f["uuid"], (body.get("triage") or "unset"), body.get("note") or "", user)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


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


# --- static SPA -------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", response_class=HTMLResponse)
def index():
    return (STATIC / "index.html").read_text(encoding="utf-8")


@app.exception_handler(401)
async def _401(request: Request, exc: HTTPException):
    return JSONResponse({"detail": "login required"}, status_code=401)
