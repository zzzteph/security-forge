"""security-forge UI — SQLite data layer.

Everything the web UI needs lives in ONE database (the user asked for all data in
the DB): users, repos (each with its cron schedule + per-repo context + scan args),
scan runs (with the full log dump), a global findings table (with mitigation
tracking + the reason a finding was mitigated), and settings. Stored in
`<DATA_ROOT>/db/security-forge-ui.db` alongside the engine's own DB.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path

DATA_ROOT = Path(os.environ.get("SECFORGE_DATA_DIR") or "/data").expanduser()
DB_PATH = DATA_ROOT / "db" / "security-forge-ui.db"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH), timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    return c


def init() -> None:
    with connect() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                pw_hash TEXT NOT NULL, pw_salt TEXT NOT NULL,
                must_change INTEGER DEFAULT 0, created TEXT, updated TEXT
            );
            CREATE TABLE IF NOT EXISTS repos (
                id INTEGER PRIMARY KEY, slug TEXT UNIQUE NOT NULL, url TEXT NOT NULL,
                name TEXT, backend TEXT DEFAULT 'litellm', model TEXT DEFAULT '',
                extra_args TEXT DEFAULT '', cron TEXT DEFAULT '', enabled INTEGER DEFAULT 1,
                context TEXT DEFAULT '',
                last_scan_id INTEGER, last_status TEXT, last_scanned TEXT,
                created TEXT, updated TEXT
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY, repo_id INTEGER, slug TEXT,
                status TEXT DEFAULT 'queued',        -- queued|running|done|error
                trigger TEXT DEFAULT 'manual',       -- manual|schedule
                commit_sha TEXT, started TEXT, finished TEXT,
                new_count INTEGER DEFAULT 0, mitigated_count INTEGER DEFAULT 0,
                total_count INTEGER DEFAULT 0, error TEXT, log TEXT DEFAULT '',
                FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,                 -- <slug>:<finding-fingerprint>
                fid TEXT, repo_id INTEGER, slug TEXT,
                severity TEXT, title TEXT, category TEXT, file TEXT, line INTEGER,
                cwe TEXT, entrypoint TEXT, reachability TEXT,
                description TEXT, impact TEXT, root_cause TEXT, remediation TEXT,
                poc TEXT, severity_rationale TEXT,
                status TEXT DEFAULT 'open',          -- open|mitigated
                mitigation_reason TEXT,
                first_seen TEXT, last_seen TEXT, fixed_at TEXT,
                first_commit TEXT, last_commit TEXT,
                first_scan_id INTEGER, last_scan_id INTEGER, raw TEXT,
                FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
            CREATE INDEX IF NOT EXISTS idx_find_repo ON findings(repo_id);
            CREATE INDEX IF NOT EXISTS idx_find_sev  ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scan_repo ON scans(repo_id);
            """
        )
        # Migration: per-repo LLM/agent args (added after first release).
        cols = {r["name"] for r in c.execute("PRAGMA table_info(repos)")}
        for name, ddl in [("base_url", "TEXT"), ("max_turns", "INTEGER"),
                          ("temperature", "TEXT"), ("timeout", "INTEGER"),
                          ("agent_cmd", "TEXT"), ("agent_output", "TEXT"),
                          ("env_json", "TEXT DEFAULT '[]'")]:
            if name not in cols:
                c.execute(f"ALTER TABLE repos ADD COLUMN {name} {ddl}")
    seed_root_user()


# Every LLM/agent arg the UI can specify + save (per repo, and as global defaults).
AGENT_FIELDS = ("backend", "model", "base_url", "max_turns", "temperature",
                "timeout", "agent_cmd", "agent_output", "extra_args")


# --- auth -------------------------------------------------------------------

def _hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()


def seed_root_user() -> None:
    with connect() as c:
        if not c.execute("SELECT 1 FROM users WHERE username='root'").fetchone():
            salt = secrets.token_hex(16)
            c.execute("INSERT INTO users(username,pw_hash,pw_salt,must_change,created,updated)"
                      " VALUES('root',?,?,1,?,?)", (_hash("root", salt), salt, _now(), _now()))


def verify_user(username: str, password: str) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if r and secrets.compare_digest(_hash(password, r["pw_salt"]), r["pw_hash"]):
        return dict(r)
    return None


def set_password(username: str, new_password: str) -> None:
    salt = secrets.token_hex(16)
    with connect() as c:
        c.execute("UPDATE users SET pw_hash=?, pw_salt=?, must_change=0, updated=? "
                  "WHERE username=?", (_hash(new_password, salt), salt, _now(), username))


def get_user(username: str) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT id,username,must_change FROM users WHERE username=?",
                      (username,)).fetchone()
    return dict(r) if r else None


# --- repos ------------------------------------------------------------------

def _slug(url: str) -> str:
    s = (url or "").strip()
    for p in ("https://", "http://", "git@", "ssh://"):
        if s.startswith(p):
            s = s[len(p):]
    s = s.replace(":", "/", 1) if s and "/" not in s.split("@")[0] else s
    if "@" in s:
        s = s.split("@", 1)[1]
    s = s[:-4] if s.endswith(".git") else s
    s = re.sub(r"[^A-Za-z0-9._/-]", "-", s.strip("/"))
    return re.sub(r"/{2,}", "/", s)


def list_repos() -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM repos ORDER BY name, slug")]


def get_repo(rid: int) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM repos WHERE id=?", (rid,)).fetchone()
    return dict(r) if r else None


def upsert_repo(data: dict, rid: int | None = None) -> int:
    url = (data.get("url") or "").strip()
    slug = _slug(url)
    def _int(v):
        try:
            return int(v) if v not in (None, "") else None
        except (TypeError, ValueError):
            return None
    env = data.get("env")
    env_json = json.dumps(env) if isinstance(env, list) else (data.get("env_json") or "[]")
    fields = {
        "url": url, "slug": slug,
        "name": (data.get("name") or slug.split("/")[-1]),
        "backend": data.get("backend") or "litellm",
        "model": data.get("model") or "",
        "base_url": (data.get("base_url") or "").strip(),
        "max_turns": _int(data.get("max_turns")),
        "temperature": (str(data.get("temperature")).strip()
                        if data.get("temperature") not in (None, "") else None),
        "timeout": _int(data.get("timeout")),
        "agent_cmd": (data.get("agent_cmd") or "").strip(),
        "agent_output": (data.get("agent_output") or "").strip(),
        "extra_args": data.get("extra_args") or "",
        "env_json": env_json,
        "cron": (data.get("cron") or "").strip(),
        "enabled": 1 if data.get("enabled", True) else 0,
        "context": data.get("context") or "",
        "updated": _now(),
    }
    with connect() as c:
        if rid:
            sets = ", ".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE repos SET {sets} WHERE id=?", (*fields.values(), rid))
            return rid
        fields["created"] = _now()
        cols = ", ".join(fields)
        c.execute(f"INSERT INTO repos ({cols}) VALUES ({', '.join('?' * len(fields))})",
                  tuple(fields.values()))
        return c.execute("SELECT id FROM repos WHERE slug=?", (slug,)).fetchone()[0]


def delete_repo(rid: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM repos WHERE id=?", (rid,))


# --- scans ------------------------------------------------------------------

def create_scan(repo_id: int, slug: str, trigger: str = "manual") -> int:
    with connect() as c:
        cur = c.execute("INSERT INTO scans(repo_id,slug,status,trigger,started) "
                        "VALUES(?,?,'queued',?,?)", (repo_id, slug, trigger, _now()))
        return cur.lastrowid


def update_scan(sid: int, **kw) -> None:
    if not kw:
        return
    sets = ", ".join(f"{k}=?" for k in kw)
    with connect() as c:
        c.execute(f"UPDATE scans SET {sets} WHERE id=?", (*kw.values(), sid))


def append_scan_log(sid: int, text: str) -> None:
    with connect() as c:
        c.execute("UPDATE scans SET log = COALESCE(log,'') || ? WHERE id=?", (text, sid))


def get_scan(sid: int) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None


def list_scans(repo_id: int | None = None, limit: int = 100) -> list[dict]:
    q = ("SELECT id,repo_id,slug,status,trigger,commit_sha,started,finished,"
         "new_count,mitigated_count,total_count,error FROM scans")
    v: list = []
    if repo_id:
        q += " WHERE repo_id=?"; v.append(repo_id)
    q += " ORDER BY id DESC LIMIT ?"; v.append(limit)
    with connect() as c:
        return [dict(r) for r in c.execute(q, tuple(v))]


# --- findings (global table + mitigation reconciliation) --------------------

def _finding_fields(f: dict) -> dict:
    cwe = f.get("cwe")
    return {
        "fid": f.get("id"),
        "severity": (f.get("severity") or "").upper(),
        "title": f.get("title"), "category": f.get("category"),
        "file": f.get("file"), "line": f.get("line"),
        "cwe": ", ".join(cwe) if isinstance(cwe, list) else (cwe or ""),
        "entrypoint": f.get("entrypoint"), "reachability": f.get("reachability"),
        "description": f.get("description"), "impact": f.get("impact"),
        "root_cause": f.get("root_cause") or f.get("why"),
        "remediation": f.get("remediation") or f.get("fix"),
        "poc": f.get("poc"), "severity_rationale": f.get("severity_rationale"),
        "raw": json.dumps(f, ensure_ascii=False, default=str),
    }


def reconcile_findings(repo_id: int, slug: str, scan_id: int,
                       new_findings: list[dict], commit: str | None) -> dict:
    """Upsert this scan's findings and MITIGATE any previously-open finding that was
    not rediscovered — recording the reason. Returns {new, mitigated, total}."""
    now = _now()
    seen_ids = set()
    n_new = 0
    with connect() as c:
        prev = {r["id"]: dict(r) for r in
                c.execute("SELECT * FROM findings WHERE repo_id=?", (repo_id,))}
        for f in new_findings:
            if not f.get("id"):
                continue
            key = f"{slug}:{f['id']}"
            seen_ids.add(key)
            fields = _finding_fields(f)
            if key in prev:
                sets = ", ".join(f"{k}=?" for k in fields)
                c.execute(f"UPDATE findings SET {sets}, status='open', mitigation_reason=NULL, "
                          f"fixed_at=NULL, last_seen=?, last_commit=?, last_scan_id=? WHERE id=?",
                          (*fields.values(), now, commit, scan_id, key))
            else:
                n_new += 1
                cols = list(fields) + ["id", "repo_id", "slug", "status", "first_seen",
                                       "last_seen", "first_commit", "last_commit",
                                       "first_scan_id", "last_scan_id"]
                vals = list(fields.values()) + [key, repo_id, slug, "open", now, now,
                                                commit, commit, scan_id, scan_id]
                c.execute(f"INSERT INTO findings ({', '.join(cols)}) "
                          f"VALUES ({', '.join('?' * len(cols))})", tuple(vals))
        # mitigate the ones that vanished
        n_mit = 0
        for key, r in prev.items():
            if key not in seen_ids and r["status"] == "open":
                n_mit += 1
                reason = (f"Not rediscovered in scan #{scan_id}"
                          + (f" at commit {commit[:8]}" if commit else "")
                          + f" ({now}); previously seen {r.get('last_seen') or r.get('first_seen')}.")
                c.execute("UPDATE findings SET status='mitigated', mitigation_reason=?, "
                          "fixed_at=? WHERE id=?", (reason, now, key))
        total = c.execute("SELECT COUNT(*) FROM findings WHERE repo_id=? AND status='open'",
                          (repo_id,)).fetchone()[0]
    return {"new": n_new, "mitigated": n_mit, "total": total}


def list_findings(status: str | None = None, repo_id: int | None = None,
                  min_sev: str | None = None) -> list[dict]:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    q = "SELECT * FROM findings"
    where, v = [], []
    if status:
        where.append("status=?"); v.append(status)
    if repo_id:
        where.append("repo_id=?"); v.append(repo_id)
    if where:
        q += " WHERE " + " AND ".join(where)
    with connect() as c:
        rows = [dict(r) for r in c.execute(q, tuple(v))]
    if min_sev:
        floor = order.get(min_sev.upper(), 0)
        rows = [r for r in rows if order.get((r.get("severity") or "").upper(), 0) >= floor]
    rows.sort(key=lambda r: order.get((r.get("severity") or "").upper(), 0), reverse=True)
    return rows


def get_finding(fid: str) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    return dict(r) if r else None


def counts() -> dict:
    with connect() as c:
        by_sev = {r["severity"]: r["n"] for r in c.execute(
            "SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity")}
        return {
            "repos": c.execute("SELECT COUNT(*) FROM repos").fetchone()[0],
            "open": c.execute("SELECT COUNT(*) FROM findings WHERE status='open'").fetchone()[0],
            "mitigated": c.execute("SELECT COUNT(*) FROM findings WHERE status='mitigated'").fetchone()[0],
            "by_severity": by_sev,
            "scans": c.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
        }


# --- settings ---------------------------------------------------------------

def get_setting(k: str, default=None):
    with connect() as c:
        r = c.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return json.loads(r["v"]) if r else default


def set_setting(k: str, value) -> None:
    with connect() as c:
        c.execute("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=?",
                  (k, json.dumps(value), json.dumps(value)))
