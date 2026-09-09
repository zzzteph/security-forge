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
                total_count INTEGER DEFAULT 0, cost_usd REAL DEFAULT 0,
                error TEXT, log TEXT DEFAULT '',
                FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,                 -- <slug>:<engine-fingerprint> (row id)
                uuid TEXT,                           -- short URL-safe web handle
                dedup_key TEXT,                       -- stable content key (title+file+cwe, NO line)
                fid TEXT, repo_id INTEGER, slug TEXT,
                severity TEXT, title TEXT, category TEXT, file TEXT, line INTEGER,
                cwe TEXT, entrypoint TEXT, reachability TEXT,
                description TEXT, impact TEXT, root_cause TEXT, remediation TEXT,
                poc TEXT, severity_rationale TEXT,
                status TEXT DEFAULT 'open',          -- open|mitigated
                mitigation_reason TEXT,
                triage TEXT DEFAULT 'unset',         -- unset|confirmed|false_positive|accepted_risk|wont_fix|duplicate
                triage_note TEXT, triaged_by TEXT, triaged_at TEXT,
                first_seen TEXT, last_seen TEXT, fixed_at TEXT,
                first_commit TEXT, last_commit TEXT,
                first_scan_id INTEGER, last_scan_id INTEGER, raw TEXT,
                FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS finding_comments (
                id INTEGER PRIMARY KEY, finding_uuid TEXT NOT NULL,
                author TEXT, body TEXT NOT NULL, created TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_comment_find ON finding_comments(finding_uuid);
            CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS skills (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '', enabled INTEGER DEFAULT 1,
                created TEXT, updated TEXT
            );
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL,
                instructions TEXT NOT NULL DEFAULT '', created TEXT, updated TEXT
            );
            CREATE TABLE IF NOT EXISTS service_cards (
                repo_id INTEGER PRIMARY KEY, slug TEXT, card_json TEXT, updated TEXT,
                FOREIGN KEY(repo_id) REFERENCES repos(id) ON DELETE CASCADE
            );
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
        # Migration: a repo can belong to a project (shared, inherited instructions).
        if "project_id" not in cols:
            c.execute("ALTER TABLE repos ADD COLUMN project_id INTEGER")
        # Migration: per-scan liveness marker (updated on every log flush) so the UI
        # can show a heartbeat / "last output N s ago" while a scan is running.
        scols = {r["name"] for r in c.execute("PRAGMA table_info(scans)")}
        if "heartbeat" not in scols:
            c.execute("ALTER TABLE scans ADD COLUMN heartbeat TEXT")
        if "cost_usd" not in scols:
            c.execute("ALTER TABLE scans ADD COLUMN cost_usd REAL DEFAULT 0")
        # Migration: short URL-safe finding handle (the composite id contains "/" and
        # ":" which break web routes). Backfill existing rows, then enforce uniqueness.
        fcols = {r["name"] for r in c.execute("PRAGMA table_info(findings)")}
        if "uuid" not in fcols:
            c.execute("ALTER TABLE findings ADD COLUMN uuid TEXT")
        for r in c.execute("SELECT id FROM findings WHERE uuid IS NULL OR uuid=''").fetchall():
            c.execute("UPDATE findings SET uuid=? WHERE id=?", (new_uuid(), r["id"]))
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_find_uuid ON findings(uuid)")
        # Migration: operator triage (a human disposition that persists across rescans
        # and is fed forward into future scans so the agent triages consistently).
        for name, ddl in [("triage", "TEXT DEFAULT 'unset'"), ("triage_note", "TEXT"),
                          ("triaged_by", "TEXT"), ("triaged_at", "TEXT")]:
            if name not in fcols:
                c.execute(f"ALTER TABLE findings ADD COLUMN {name} {ddl}")
        # Migration: stable content dedup key (the engine id bakes in the line number,
        # so a rescan that sees the same bug on a shifted line looked "new" and piled
        # up duplicates). Backfill, then collapse any duplicates already recorded.
        if "dedup_key" not in fcols:
            c.execute("ALTER TABLE findings ADD COLUMN dedup_key TEXT")
        for r in c.execute("SELECT id,slug,title,file,cwe,category FROM findings "
                           "WHERE dedup_key IS NULL OR dedup_key=''").fetchall():
            c.execute("UPDATE findings SET dedup_key=? WHERE id=?",
                      (_dedup_key(r["slug"], dict(r)), r["id"]))
        c.execute("CREATE INDEX IF NOT EXISTS idx_find_dedup ON findings(repo_id,dedup_key)")
    _collapse_duplicate_findings()
    seed_root_user()


def new_uuid() -> str:
    """Short, URL-safe, collision-resistant handle for a finding (16 hex chars)."""
    return secrets.token_hex(8)


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


def repo_by_url(url: str) -> dict | None:
    """Find an existing repo by the slug its URL normalizes to (so http/https,
    trailing .git, and case differences all resolve to the same repo)."""
    slug = _slug(url or "")
    if not slug:
        return None
    with connect() as c:
        r = c.execute("SELECT * FROM repos WHERE slug=?", (slug,)).fetchone()
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
        "project_id": _int(data.get("project_id")),
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
    q = ("SELECT id,repo_id,slug,status,trigger,commit_sha,started,finished,heartbeat,"
         "new_count,mitigated_count,total_count,cost_usd,error FROM scans")
    v: list = []
    if repo_id:
        q += " WHERE repo_id=?"; v.append(repo_id)
    q += " ORDER BY id DESC LIMIT ?"; v.append(limit)
    with connect() as c:
        return [dict(r) for r in c.execute(q, tuple(v))]


def delete_scan(sid: int) -> None:
    """Remove a scan run (its log + counters). Findings are keyed on repo, not on the
    scan, so they are untouched; only the run record disappears."""
    with connect() as c:
        c.execute("DELETE FROM scans WHERE id=?", (sid,))
        # If a repo pointed at this scan as its 'last', clear the dangling reference.
        c.execute("UPDATE repos SET last_scan_id=NULL WHERE last_scan_id=?", (sid,))


# --- findings (global table + mitigation reconciliation) --------------------

def _dedup_key(slug: str, f: dict) -> str:
    """A stable identity for a finding that survives rescans. Deliberately EXCLUDES the
    line number (it drifts as code moves and made the engine re-id the same bug) and
    normalizes the title so minor rewordings collapse to one finding."""
    title = re.sub(r"[^a-z0-9]+", " ", (f.get("title") or "").lower()).strip()
    file = (f.get("file") or "").replace("\\", "/").lstrip("./").strip().lower()
    cwe = f.get("cwe")
    cwe = ",".join(cwe) if isinstance(cwe, list) else (cwe or "")
    cat = (f.get("category") or "").strip().lower()
    basis = "|".join([slug or "", file, title, str(cwe).lower(), cat])
    return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]


def _collapse_duplicate_findings() -> None:
    """One-time cleanup: fold pre-existing duplicate rows (same repo + dedup_key) into a
    single finding, preserving triage and moving comments to the survivor. Idempotent."""
    with connect() as c:
        groups = c.execute(
            "SELECT repo_id, dedup_key, COUNT(*) n FROM findings "
            "WHERE dedup_key IS NOT NULL AND dedup_key!='' "
            "GROUP BY repo_id, dedup_key HAVING n>1").fetchall()
        for g in groups:
            rows = [dict(r) for r in c.execute(
                "SELECT * FROM findings WHERE repo_id=? AND dedup_key=? "
                "ORDER BY (first_seen IS NULL), first_seen, id",
                (g["repo_id"], g["dedup_key"]))]
            survivor = rows[0]
            losers = rows[1:]
            # survivor inherits the strongest signal from the group
            triage = next((r["triage"] for r in rows
                           if (r.get("triage") or "unset") != "unset"), survivor.get("triage"))
            note = next((r["triage_note"] for r in rows if r.get("triage_note")), survivor.get("triage_note"))
            open_now = 1 if any((r.get("status") == "open") for r in rows) else 0
            last_seen = max((r.get("last_seen") or "") for r in rows)
            c.execute("UPDATE findings SET triage=?, triage_note=?, status=?, last_seen=? WHERE id=?",
                      (triage or "unset", note, "open" if open_now else "mitigated",
                       last_seen or survivor.get("last_seen"), survivor["id"]))
            for r in losers:
                c.execute("UPDATE finding_comments SET finding_uuid=? WHERE finding_uuid=?",
                          (survivor["uuid"], r["uuid"]))
                c.execute("DELETE FROM findings WHERE id=?", (r["id"],))


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
        # Map each existing row's stable content key -> its row id, so a rescan that
        # reports the same bug (even at a shifted line, hence a different engine id)
        # updates the SAME row instead of adding a duplicate.
        dk_to_id: dict[str, str] = {}
        for rid_, r in prev.items():
            dk = r.get("dedup_key") or _dedup_key(slug, r)
            dk_to_id.setdefault(dk, rid_)
        for f in new_findings:
            if not f.get("id"):
                continue
            dk = _dedup_key(slug, f)
            fields = _finding_fields(f)
            fields["dedup_key"] = dk
            # resolve which row this finding belongs to: prefer a same-content row,
            # else the engine-id row, else it's genuinely new.
            key = dk_to_id.get(dk) or f"{slug}:{f['id']}"
            if key in prev or key in seen_ids:
                seen_ids.add(key)
                dk_to_id.setdefault(dk, key)
                sets = ", ".join(f"{k}=?" for k in fields)
                c.execute(f"UPDATE findings SET {sets}, status='open', mitigation_reason=NULL, "
                          f"fixed_at=NULL, last_seen=?, last_commit=?, last_scan_id=? WHERE id=?",
                          (*fields.values(), now, commit, scan_id, key))
            else:
                n_new += 1
                cols = list(fields) + ["id", "uuid", "repo_id", "slug", "status", "first_seen",
                                       "last_seen", "first_commit", "last_commit",
                                       "first_scan_id", "last_scan_id"]
                vals = list(fields.values()) + [key, new_uuid(), repo_id, slug, "open", now, now,
                                                commit, commit, scan_id, scan_id]
                c.execute(f"INSERT INTO findings ({', '.join(cols)}) "
                          f"VALUES ({', '.join('?' * len(cols))})", tuple(vals))
                seen_ids.add(key)
                dk_to_id[dk] = key
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


def list_findings_by_scan(scan_id: int) -> list[dict]:
    """Findings surfaced by a specific scan (i.e. present/updated in that run),
    most-severe first — for the per-scan findings table in the UI."""
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT id,uuid,slug,severity,title,category,file,line,status,triage,"
            "first_scan_id,last_scan_id FROM findings WHERE last_scan_id=?", (scan_id,))]
    rows.sort(key=lambda r: order.get((r.get("severity") or "").upper(), 0), reverse=True)
    return rows


def get_finding(key: str) -> dict | None:
    """Resolve a finding by its short uuid handle (what the UI links to) or, as a
    fallback, by its composite id."""
    with connect() as c:
        r = c.execute("SELECT * FROM findings WHERE uuid=?", (key,)).fetchone()
        if not r:
            r = c.execute("SELECT * FROM findings WHERE id=?", (key,)).fetchone()
    return dict(r) if r else None


# --- triage + comments (operator disposition; fed forward into future scans) ------

TRIAGE_VALUES = ("unset", "confirmed", "false_positive", "accepted_risk",
                 "wont_fix", "duplicate")
# The dispositions that mean "reviewed, not something to re-raise as-is" — these are
# the ones worth feeding forward so the agent doesn't keep re-reporting them.
TRIAGE_DISMISSED = ("false_positive", "accepted_risk", "wont_fix", "duplicate")
TRIAGE_LABEL = {"unset": "Untriaged", "confirmed": "Confirmed",
                "false_positive": "False positive", "accepted_risk": "Accepted risk",
                "wont_fix": "Won't fix", "duplicate": "Duplicate"}


def set_triage(uuid: str, triage: str, note: str, user: str) -> bool:
    if triage not in TRIAGE_VALUES:
        raise ValueError(f"invalid triage '{triage}'")
    with connect() as c:
        cur = c.execute("UPDATE findings SET triage=?, triage_note=?, triaged_by=?, "
                        "triaged_at=? WHERE uuid=?",
                        (triage, (note or "").strip() or None, user, _now(), uuid))
    return cur.rowcount > 0


def add_comment(finding_uuid: str, author: str, body: str) -> dict:
    body = (body or "").strip()
    if not body:
        raise ValueError("empty comment")
    with connect() as c:
        cur = c.execute("INSERT INTO finding_comments(finding_uuid,author,body,created) "
                        "VALUES(?,?,?,?)", (finding_uuid, author, body, _now()))
        r = c.execute("SELECT * FROM finding_comments WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(r)


def list_comments(finding_uuid: str) -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM finding_comments WHERE finding_uuid=? ORDER BY id", (finding_uuid,))]


# --- skills (operator-uploaded .md playbooks, injected into every scan) ----------

def list_skills() -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT id,name,enabled,LENGTH(content) AS size,created,updated "
            "FROM skills ORDER BY name")]


def get_skill(sid: int) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM skills WHERE id=?", (sid,)).fetchone()
    return dict(r) if r else None


def upsert_skill(data: dict, sid: int | None = None) -> int:
    name = (data.get("name") or "skill").strip()[:120]
    content = data.get("content") or ""
    enabled = 1 if data.get("enabled", True) else 0
    with connect() as c:
        if sid:
            c.execute("UPDATE skills SET name=?, content=?, enabled=?, updated=? WHERE id=?",
                      (name, content, enabled, _now(), sid))
            return sid
        cur = c.execute("INSERT INTO skills(name,content,enabled,created,updated) "
                        "VALUES(?,?,?,?,?)", (name, content, enabled, _now(), _now()))
        return cur.lastrowid


def delete_skill(sid: int) -> None:
    with connect() as c:
        c.execute("DELETE FROM skills WHERE id=?", (sid,))


def enabled_skills_text(per_skill_cap: int = 12000) -> str:
    """Concatenate the ENABLED skills into one authoritative block for the scan
    context. Each skill is capped so one huge doc can't blow the prompt; the full
    text is always available in the UI."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT name,content FROM skills WHERE enabled=1 ORDER BY name")]
    rows = [r for r in rows if (r.get("content") or "").strip()]
    if not rows:
        return ""
    parts = ["ENABLED ANALYSIS SKILLS — operator-provided playbooks/rules you MUST "
             "apply on this scan (in addition to opt/workflow.md). Follow every one:"]
    for r in rows:
        body = (r["content"] or "").strip()
        if len(body) > per_skill_cap:
            body = body[:per_skill_cap] + "\n…(truncated — see the full skill in the UI)"
        parts.append(f"\n===== SKILL: {r['name']} =====\n{body}")
    return "\n".join(parts)


# --- projects (a group of repos sharing inherited ground-truth instructions) -----

def list_projects() -> list[dict]:
    with connect() as c:
        return [dict(r) for r in c.execute(
            "SELECT p.id, p.name, p.instructions, p.updated, "
            "(SELECT COUNT(*) FROM repos r WHERE r.project_id=p.id) AS repo_count "
            "FROM projects p ORDER BY p.name")]


def get_project(pid: int) -> dict | None:
    with connect() as c:
        r = c.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["repos"] = [dict(x) for x in c.execute(
            "SELECT id, slug FROM repos WHERE project_id=? ORDER BY slug", (pid,))]
        return d


def upsert_project(data: dict, pid: int | None = None) -> int:
    name = (data.get("name") or "project").strip()[:120]
    instr = data.get("instructions") or ""
    with connect() as c:
        if pid:
            c.execute("UPDATE projects SET name=?, instructions=?, updated=? WHERE id=?",
                      (name, instr, _now(), pid))
            return pid
        cur = c.execute("INSERT INTO projects(name,instructions,created,updated) "
                        "VALUES(?,?,?,?)", (name, instr, _now(), _now()))
        return cur.lastrowid


def delete_project(pid: int) -> None:
    with connect() as c:
        c.execute("UPDATE repos SET project_id=NULL WHERE project_id=?", (pid,))
        c.execute("DELETE FROM projects WHERE id=?", (pid,))


def build_card_from_model(model: dict) -> dict:
    """Distill a repo's recon model.json into a compact SERVICE CARD — what it
    exposes, how it authenticates/authorizes, and (the cross-service key) what it
    CALLS. This is the shared knowledge a project accumulates; the code is never
    shared, only these cards."""
    exposes = []
    for e in (model.get("entrypoints") or [])[:300]:
        if isinstance(e, dict):
            exposes.append({"method": e.get("method") or e.get("kind") or "",
                            "route": e.get("route") or e.get("id") or "",
                            "auth_required": e.get("auth_required"),
                            "roles": e.get("roles") or []})
    auth = model.get("auth") or {}
    raw_calls = (model.get("calls") or model.get("dependencies")
                 or model.get("outbound_calls") or model.get("outbound") or [])
    calls = []
    for c in (raw_calls if isinstance(raw_calls, list) else [])[:200]:
        if isinstance(c, str):
            calls.append({"target": c})
        elif isinstance(c, dict):
            calls.append({k: c.get(k) for k in ("target", "kind", "where", "auth_sent")
                          if c.get(k)})
    return {"idea": (model.get("idea") or "")[:400],
            "authn": auth.get("authn") or {}, "authz": auth.get("authz") or {},
            "exposes": exposes, "calls": calls, "provides": model.get("provides") or [],
            "built_commit": model.get("last_analyzed_commit") or model.get("built_commit")}


def upsert_service_card(repo_id: int, slug: str, card: dict) -> None:
    cj = json.dumps(card, ensure_ascii=False)
    with connect() as c:
        c.execute("INSERT INTO service_cards(repo_id,slug,card_json,updated) "
                  "VALUES(?,?,?,?) ON CONFLICT(repo_id) DO UPDATE SET "
                  "slug=excluded.slug, card_json=excluded.card_json, updated=excluded.updated",
                  (repo_id, slug, cj, _now()))


def _card_to_prose(slug: str, card: dict) -> str:
    out = [f"### {slug}"]
    if card.get("idea"):
        out.append(f"  purpose: {card['idea']}")
    ex = card.get("exposes") or []
    if ex:
        shown = "; ".join(
            f"{(e.get('method') or '').upper()} {e.get('route') or ''}"
            + (" [auth]" if e.get("auth_required") else " [NO auth]"
               if e.get("auth_required") is False else "")
            + (f" roles={','.join(e['roles'])}" if e.get("roles") else "")
            for e in ex[:40])
        out.append(f"  exposes: {shown}" + (f"  (+{len(ex) - 40} more)" if len(ex) > 40 else ""))
    authn, authz = card.get("authn") or {}, card.get("authz") or {}
    if authn.get("mechanism") or authz.get("model"):
        out.append(f"  auth: authn={authn.get('mechanism', '?')}; authz={authz.get('model', '?')}"
                   + (f"; enforced_at={authz.get('enforced_at')}" if authz.get("enforced_at") else ""))
    if card.get("calls"):
        out.append("  calls (outbound): " + ", ".join(
            x.get("target", "?") for x in card["calls"][:40]))
    if card.get("provides"):
        out.append(f"  provides: {card['provides']}")
    return "\n".join(out)


def project_service_map(repo_id: int) -> str:
    """The OTHER services in this repo's project, as cards, for injection into the
    scan context — so a service is validated against what its neighbors DECLARE
    (auth, exposure, outbound calls) without cloning their code."""
    with connect() as c:
        r = c.execute("SELECT project_id FROM repos WHERE id=?", (repo_id,)).fetchone()
        if not r or r["project_id"] is None:
            return ""
        rows = [dict(x) for x in c.execute(
            "SELECT sc.slug AS slug, sc.card_json AS card_json FROM service_cards sc "
            "JOIN repos rp ON rp.id = sc.repo_id "
            "WHERE rp.project_id=? AND sc.repo_id != ?", (r["project_id"], repo_id))]
    if not rows:
        return ""
    parts = ["PROJECT SERVICE MAP — the OTHER services in this project (shared knowledge, "
             "NOT their code). Use them to resolve cross-service auth and reachability: if "
             "this service calls one listed below, trust its declared auth/exposure and do "
             "not re-flag it; a call to a service NOT listed here is UNMODELED — say so "
             "rather than assume it's unprotected."]
    for row in rows:
        try:
            parts.append(_card_to_prose(row["slug"], json.loads(row["card_json"])))
        except (ValueError, TypeError):
            continue
    return "\n".join(parts)


def project_instructions(repo_id: int) -> str:
    """The instructions of the project this repo belongs to (shared across members),
    for injection into the repo's scan context. Empty if it has no project."""
    with connect() as c:
        r = c.execute("SELECT p.name, p.instructions FROM repos rp "
                      "JOIN projects p ON p.id = rp.project_id WHERE rp.id=?",
                      (repo_id,)).fetchone()
    if not r or not (r["instructions"] or "").strip():
        return ""
    return (f"PROJECT-WIDE GROUND TRUTH — applies to every repo in project "
            f"\"{r['name']}\"; treat as authoritative fact and obey it (do NOT report "
            f"anything it declares handled/secure):\n{r['instructions'].strip()}")


def triage_context(repo_id: int) -> str:
    """A prose block of the operator's prior triage decisions AND comments for a repo,
    injected into the next scan's context so the agent stays consistent — it stops
    re-reporting findings a human dismissed, and it honors free-form comments (e.g.
    'this id is a public UUID, safe to expose' / 'auth is enforced in the gateway')."""
    with connect() as c:
        rows = [dict(r) for r in c.execute(
            "SELECT severity,title,file,line,triage,triage_note FROM findings "
            "WHERE repo_id=? AND triage IS NOT NULL AND triage!='unset' "
            "ORDER BY triage, severity", (repo_id,))]
        crows = [dict(r) for r in c.execute(
            "SELECT f.severity AS severity, f.title AS title, f.file AS file, "
            "f.line AS line, fc.body AS body FROM finding_comments fc "
            "JOIN findings f ON f.uuid = fc.finding_uuid "
            "WHERE f.repo_id=? ORDER BY f.id, fc.id", (repo_id,))]
    if not rows and not crows:
        return ""
    dismissed = [r for r in rows if r["triage"] in TRIAGE_DISMISSED]
    confirmed = [r for r in rows if r["triage"] == "confirmed"]

    def _where(r: dict) -> str:
        w = (r.get("file") or "")
        return w + (f":{r['line']}" if w and r.get("line") else "")

    def _line(r: dict) -> str:
        why = (r.get("triage_note") or "").strip()
        w = _where(r)
        return (f"- [{TRIAGE_LABEL.get(r['triage'], r['triage'])}] "
                f"{(r.get('severity') or '').upper()} {r.get('title') or '(untitled)'}"
                + (f" ({w})" if w else "") + (f" -- reason: {why}" if why else ""))

    parts: list[str] = []
    if rows:
        parts.append("PRIOR HUMAN TRIAGE for THIS repository (authoritative -- respect "
                     "these decisions and triage new findings consistently with them):")
        if dismissed:
            parts.append("Already reviewed and DISMISSED -- do NOT re-report these as new "
                         "issues; if you still see the same code, treat it as a known, "
                         "accepted decision and do not raise it again:")
            parts += [_line(r) for r in dismissed]
        if confirmed:
            parts.append("Previously CONFIRMED as real (still valid to report if present):")
            parts += [_line(r) for r in confirmed]
    if crows:
        parts.append("OPERATOR COMMENTS on specific findings (authoritative guidance "
                     "from the human reviewer -- honor them exactly: if a comment says "
                     "an id/endpoint/finding is safe, intentional, or handled elsewhere, "
                     "do NOT report it or anything equivalent):")
        for r in crows:
            body = (r.get("body") or "").strip()
            if not body:
                continue
            w = _where(r)
            parts.append(f"- on \"{r.get('title') or '(untitled)'}\""
                         + (f" ({w})" if w else "") + f": {body}")
    parts.append("Apply the same reasoning to similar new findings before recording them.")
    return "\n".join(parts)


# --- reviewer aid: "why this might be a false positive" ---------------------------
# HINTS ONLY. These never change a finding's status — they hand the human reviewer a
# head start by surfacing the project's accumulated shared knowledge (ground-truth
# instructions, sibling service cards, prior triage, reviewer comments) that could
# explain this finding away. The reviewer decides; this just tells them where to look.

_HINT_STOP = {
    "the", "and", "for", "with", "that", "this", "from", "have", "which", "when", "into",
    "your", "their", "then", "than", "will", "would", "could", "should", "there", "where",
    "does", "done", "only", "also", "some", "such", "been", "being", "were", "was", "are",
    "not", "but", "can", "may", "via", "use", "used", "using", "http", "https", "request",
    "requests", "response", "value", "values", "field", "fields", "data", "code", "line",
    "file", "files", "function", "method", "methods", "call", "calls", "input", "name",
    "endpoint", "endpoints", "route", "routes", "found", "issue", "finding", "allows",
}
# security-domain signals: an overlap on ANY of these is meaningful on its own.
_AUTH_SIGNALS = {
    "auth", "authentication", "authorization", "authorize", "authz", "authn", "jwt", "jwk",
    "token", "tokens", "session", "cookie", "cookies", "oauth", "oidc", "okta", "saml",
    "login", "logout", "credential", "credentials", "permission", "permissions", "role",
    "roles", "rbac", "abac", "acl", "access", "idor", "ownership", "owner", "tenant",
    "tenancy", "csrf", "cors", "gateway", "middleware", "guard", "identity", "principal",
    "unauthenticated", "unauthorized", "privilege", "escalation",
}


# short security acronyms worth matching despite being under the length floor.
_SHORT_SIGNALS = {"jwt", "jwk", "sql", "xss", "acl", "sso", "mfa", "otp", "xxe",
                  "rce", "iam", "kms", "api"}


def _hint_terms(*texts: str) -> set[str]:
    out: set[str] = set()
    for t in texts:
        for tok in re.split(r"[^a-z0-9]+", (t or "").lower()):
            if tok in _HINT_STOP:
                continue
            if len(tok) >= 4 or tok in _SHORT_SIGNALS:
                out.add(tok)
    return out


def _hint_auth_related(terms: set[str], f: dict) -> bool:
    cat = (f.get("category") or "").lower()
    if any(k in cat for k in ("auth", "idor", "access", "privil", "tenant",
                              "object-level", "function-level", "broken", "ssrf")):
        return True
    return bool(terms & _AUTH_SIGNALS)


def review_hints(f: dict) -> list[dict]:
    """Non-authoritative reasons THIS finding might be a false positive, drawn from the
    project's accumulated shared knowledge. Returns [{source, reason}]. HINTS ONLY —
    they never change status; the reviewer decides. Computed at read time so they always
    reflect the latest project instructions, sibling cards, triage and comments."""
    repo_id = f.get("repo_id")
    if not repo_id:
        return []
    fterms = _hint_terms(f.get("title"), f.get("category"), f.get("description"),
                         f.get("entrypoint"), f.get("cwe"))
    auth_related = _hint_auth_related(fterms, f)
    my_uuid = f.get("uuid") or ""
    hints: list[dict] = []
    with connect() as c:
        prow = c.execute(
            "SELECT p.id AS pid, p.name AS name, p.instructions AS instr "
            "FROM repos rp JOIN projects p ON p.id=rp.project_id WHERE rp.id=?",
            (repo_id,)).fetchone()
        project = dict(prow) if prow else None

        # 1) project ground-truth lines that overlap this finding.
        if project and (project["instr"] or "").strip():
            for raw in project["instr"].splitlines():
                ln = raw.strip(" -*\t•")
                if len(ln) < 6:
                    continue
                shared = fterms & _hint_terms(ln)
                if (shared & _AUTH_SIGNALS) or len(shared) >= 2:
                    hints.append({
                        "source": f"Project ground truth ({project['name']})",
                        "reason": f"The project declares as fact: “{ln}” — if this "
                                  "finding is that same mechanism, it may already be handled."})
                if len(hints) >= 2:
                    break

        # scope for prior triage / comments: the whole project if grouped, else this repo.
        scope_ids = [repo_id]
        if project:
            sib = [r["id"] for r in c.execute(
                "SELECT id FROM repos WHERE project_id=?", (project["pid"],))]
            if sib:
                scope_ids = sib
        qmarks = ",".join("?" * len(scope_ids))

        # 2) sibling service cards — auth enforced elsewhere, or the caller is authed.
        if auth_related and project:
            for s in c.execute(
                    "SELECT sc.slug AS slug, sc.card_json AS cj FROM service_cards sc "
                    "JOIN repos rp ON rp.id=sc.repo_id WHERE rp.project_id=? AND sc.repo_id!=?",
                    (project["pid"], repo_id)).fetchall():
                try:
                    card = json.loads(s["cj"])
                except (ValueError, TypeError):
                    continue
                enf = (card.get("authz") or {}).get("enforced_at")
                if enf:
                    hints.append({
                        "source": f"Sibling service “{s['slug']}”",
                        "reason": f"“{s['slug']}” enforces authorization at {enf}. If this "
                                  "endpoint sits behind that shared boundary (e.g. a gateway), the "
                                  "missing local check may be enforced upstream."})
                ep = (f.get("entrypoint") or "").split()
                ep_tail = ep[-1] if ep else ""
                for call in (card.get("calls") or []):
                    tgt = call.get("target") or ""
                    if call.get("auth_sent") and tgt and ep_tail and ep_tail in tgt:
                        hints.append({
                            "source": f"Sibling service “{s['slug']}”",
                            "reason": f"“{s['slug']}” calls {tgt} sending {call['auth_sent']} — "
                                      "the caller is authenticated, so an ‘unauthenticated’ "
                                      "reach here may be internal service-to-service traffic."})
                if len(hints) >= 5:
                    break

        # 3) prior findings a human already DISMISSED that look similar.
        for r in c.execute(
                f"SELECT title, category, triage, triage_note FROM findings "
                f"WHERE repo_id IN ({qmarks}) AND triage IN "
                f"({','.join('?' * len(TRIAGE_DISMISSED))}) AND uuid!=?",
                (*scope_ids, *TRIAGE_DISMISSED, my_uuid)).fetchall():
            same_cat = bool(r["category"]) and \
                (r["category"] or "").lower() == (f.get("category") or "").lower()
            if same_cat or len(_hint_terms(r["title"]) & fterms) >= 2:
                note = (r["triage_note"] or "").strip()
                hints.append({
                    "source": f"Prior triage — {TRIAGE_LABEL.get(r['triage'], r['triage'])}",
                    "reason": f"A similar finding was dismissed: “{r['title']}”"
                              + (f" — reviewer noted: “{note}”" if note else "")
                              + ". Consider whether the same reasoning applies here."})
            if len(hints) >= 7:
                break

        # 4) reviewer comments left on related findings.
        for r in c.execute(
                f"SELECT f.title AS title, fc.body AS body FROM finding_comments fc "
                f"JOIN findings f ON f.uuid=fc.finding_uuid "
                f"WHERE f.repo_id IN ({qmarks}) AND f.uuid!=?",
                (*scope_ids, my_uuid)).fetchall():
            body = (r["body"] or "").strip()
            if body and len(_hint_terms(r["title"], body) & fterms) >= 2:
                hints.append({
                    "source": "Reviewer note on a related finding",
                    "reason": f"On “{r['title']}” a reviewer wrote: “{body}”"})
            if len(hints) >= 9:
                break

    seen: set[str] = set()
    uniq: list[dict] = []
    for h in hints:
        if h["reason"] in seen:
            continue
        seen.add(h["reason"])
        uniq.append(h)
    return uniq[:6]


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
            "cost_usd": c.execute("SELECT COALESCE(SUM(cost_usd),0) FROM scans").fetchone()[0],
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
