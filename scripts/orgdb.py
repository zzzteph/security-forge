"""security-forge durable database — the ledger of analyzed repos + their vulns.

This is the single, queryable store the orchestrator keeps across runs. It uses
SQLite (Python stdlib, no extra dep) so one copy of security-forge can track a
whole GitHub org (hundreds/thousands of repos) and answer cheap "have we already
analyzed <repo>@<commit>?" lookups that drive incremental, resumable batches.

Two tables:
  targets   one row per repo (keyed by slug host/owner/repo): the clone URL, the
            org, the latest push, and how far security-forge has gotten with it
            (status + analyzed_commit). This is the batch queue AND the ledger.
  findings  one row per MEDIUM/HIGH/CRITICAL finding, keyed by a stable id and
            tagged with the repo slug + the commit it was found in. Mirrors each
            target's findings.json into one place for cross-repo querying.

The DB lives at db/security-forge.db under DATA_ROOT (durable, NOT gitignored) so
it persists between runs and can be committed as the project's memory — the
"knowledge of all repos" in one file.

CLI:
    python scripts/orgdb.py init
    python scripts/orgdb.py summary
    python scripts/orgdb.py add --repo https://github.com/owner/repo
    python scripts/orgdb.py targets [--status analyzed] [--limit 50]
    python scripts/orgdb.py findings [--slug github.com/o/r] [--min-sev HIGH]
    python scripts/orgdb.py next-batch [--count 10]
    python scripts/orgdb.py show --slug github.com/owner/repo
    python scripts/orgdb.py set-status --slug <slug> --status analyzing
    python scripts/orgdb.py reap-stale [--max-attempts 2]
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_ROOT, now_iso, sev_rank, target_slug, configure_stdio  # noqa: E402

configure_stdio()

DB_DIR = DATA_ROOT / "db"
DB_PATH = DB_DIR / "security-forge.db"

# Repo lifecycle:
#   seen        enqueued (org sync or `add`), not yet touched
#   cloning     a session is cloning/prepping it
#   analyzing   a session is analyzing it
#   analyzed    a full cycle finished for its current commit
#   error       a cycle failed / aborted (retried next run)
#   skipped     deliberately excluded (archived, too many aborts, filtered out)
TARGET_STATUS = {"seen", "cloning", "analyzing", "analyzed", "error", "skipped"}


def _connect() -> sqlite3.Connection:
    DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    # DELETE journal (not WAL): each committed txn lands fully in the single .db
    # file with no -wal/-shm sidecars, so the DB is always clean to commit to git.
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init() -> dict:
    with _connect() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS targets (
                slug              TEXT PRIMARY KEY,   -- host/owner/repo (filesystem key)
                repo_url          TEXT,               -- clone/analyze URL
                name              TEXT,               -- owner/repo
                org               TEXT,
                default_branch    TEXT,
                pushed_at         TEXT,               -- GitHub last push (freshness)
                size_kb           INTEGER DEFAULT 0,
                private           INTEGER DEFAULT 0,
                archived          INTEGER DEFAULT 0,
                fork              INTEGER DEFAULT 0,
                language          TEXT,
                description       TEXT,
                homepage          TEXT,
                first_seen        TEXT,
                status            TEXT DEFAULT 'seen',
                analyzed_commit   TEXT,
                analyzed_at       TEXT,
                analyzed_pushed_at TEXT,           -- pushed_at snapshot at analysis time (diff detection)
                error             TEXT,
                attempts          INTEGER DEFAULT 0,
                medium_count      INTEGER DEFAULT 0,
                high_count        INTEGER DEFAULT 0,
                critical_count    INTEGER DEFAULT 0,
                updated           TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id                TEXT PRIMARY KEY,
                slug              TEXT NOT NULL,
                commit_sha        TEXT,
                severity          TEXT,
                category          TEXT,
                title             TEXT,
                file              TEXT,
                line              INTEGER,
                cwe               TEXT,          -- JSON array
                entrypoint        TEXT,
                reachability      TEXT,
                poc               TEXT,
                evidence          TEXT,
                status            TEXT,          -- new/triaged/verifying/verified/dismissed/fixed
                verdict           TEXT,
                reported          INTEGER DEFAULT 0,
                fix_reported      INTEGER DEFAULT 0,
                first_seen        TEXT,
                last_seen         TEXT,
                updated           TEXT,
                FOREIGN KEY (slug) REFERENCES targets (slug)
            );

            CREATE INDEX IF NOT EXISTS idx_targets_status  ON targets (status);
            CREATE INDEX IF NOT EXISTS idx_targets_pushed  ON targets (pushed_at);
            CREATE INDEX IF NOT EXISTS idx_findings_slug   ON findings (slug);
            CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings (severity);
            """
        )
        # Migration: analyzed_pushed_at (added after first release) for older DBs.
        cols = {r["name"] for r in c.execute("PRAGMA table_info(targets)")}
        if "analyzed_pushed_at" not in cols:
            c.execute("ALTER TABLE targets ADD COLUMN analyzed_pushed_at TEXT")
    return {"db": str(DB_PATH), "initialized": True}


def reap_stale(max_attempts: int = 2) -> dict:
    """Reap repos left mid-flight by an aborted session (crash, timeout kill, or a
    platform safeguard). A repo still marked `cloning`/`analyzing` when a new run
    starts means a prior session died on it: bump attempts, and once it has burned
    `max_attempts` retries mark it `skipped` so it stops poisoning the queue
    (`next_batch` never returns `skipped`). Otherwise mark it `error` for one more
    try. Returns what was reaped so the caller can log it."""
    init()
    retried, skipped = [], []
    with _connect() as c:
        rows = c.execute(
            "SELECT slug, attempts FROM targets WHERE status IN ('cloning','analyzing')"
        ).fetchall()
        for r in rows:
            n = (r["attempts"] or 0) + 1
            if n >= max_attempts:
                c.execute("UPDATE targets SET status='skipped', attempts=?, "
                          "error='aborted x'||?||' (crash/timeout/safeguard) — skipped', "
                          "updated=? WHERE slug=?", (n, n, now_iso(), r["slug"]))
                skipped.append(r["slug"])
            else:
                c.execute("UPDATE targets SET status='error', attempts=?, "
                          "error='prior session aborted mid-analysis', updated=? "
                          "WHERE slug=?", (n, now_iso(), r["slug"]))
                retried.append(r["slug"])
    return {"reaped": len(retried) + len(skipped), "retry": retried, "skipped": skipped}


# --- Target queue -----------------------------------------------------------

def upsert_target(info: dict) -> str:
    """Insert or refresh a repo row from a GitHub API record (or a plain
    {repo_url}). Preserves analysis progress (status/analyzed_commit). Returns
    the slug."""
    url = (info.get("repo_url") or info.get("clone_url") or info.get("html_url") or "").strip()
    slug = (info.get("slug") or target_slug(url)).strip()
    if not slug:
        raise ValueError("target info has no repo_url/slug")
    init()
    with _connect() as c:
        row = c.execute("SELECT slug FROM targets WHERE slug=?", (slug,)).fetchone()
        fields = {
            "repo_url": url or (row and c.execute("SELECT repo_url FROM targets WHERE slug=?", (slug,)).fetchone()[0]),
            "name": info.get("name") or info.get("full_name"),
            "org": info.get("org") or (info.get("owner") or {}).get("login") if isinstance(info.get("owner"), dict) else info.get("org"),
            "default_branch": info.get("default_branch"),
            "pushed_at": info.get("pushed_at"),
            "size_kb": int(info.get("size") or 0),
            "private": 1 if info.get("private") else 0,
            "archived": 1 if info.get("archived") else 0,
            "fork": 1 if info.get("fork") else 0,
            "language": info.get("language"),
            "description": (info.get("description") or "")[:500],
            "homepage": info.get("homepage"),
            "updated": now_iso(),
        }
        fields = {k: v for k, v in fields.items() if v is not None}
        if row:
            sets = ", ".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE targets SET {sets} WHERE slug=?", (*fields.values(), slug))
        else:
            fields["slug"] = slug
            fields.setdefault("repo_url", url)
            fields["first_seen"] = now_iso()
            fields["status"] = "seen"
            cols = ", ".join(fields)
            qs = ", ".join("?" for _ in fields)
            c.execute(f"INSERT INTO targets ({cols}) VALUES ({qs})", tuple(fields.values()))
    return slug


def set_status(slug: str, status: str, error: str | None = None,
               analyzed_commit: str | None = None) -> None:
    if status not in TARGET_STATUS:
        raise SystemExit(f"invalid status '{status}'. one of {sorted(TARGET_STATUS)}")
    init()
    with _connect() as c:
        sets = ["status=?", "updated=?"]
        vals: list = [status, now_iso()]
        if error is not None:
            sets.append("error=?"); vals.append(error[:1000])
        if analyzed_commit is not None:
            sets += ["analyzed_commit=?", "analyzed_at=?"]
            vals += [analyzed_commit, now_iso()]
        if status == "analyzed":
            # snapshot the current push marker so a later `--rescan` re-queues this
            # repo iff its upstream pushed_at changes (exact compare, no TZ math).
            sets.append("analyzed_pushed_at=pushed_at")
        vals.append(slug)
        c.execute(f"UPDATE targets SET {', '.join(sets)} WHERE slug=?", tuple(vals))


def get(slug: str) -> dict | None:
    init()
    with _connect() as c:
        row = c.execute("SELECT * FROM targets WHERE slug=?", (slug,)).fetchone()
        return dict(row) if row else None


def next_batch(count: int = 10, pushed_since: str | None = None,
               rescan: bool = False) -> list[dict]:
    """Repos due for analysis, freshest push first.

    Default (initial sweep): never-analyzed repos + any left in `error`.
    rescan=True: ALSO re-queue analyzed repos whose upstream `pushed_at` differs
    from the snapshot taken when we last analyzed them — i.e. a repo that got new
    commits (a diff) since. The per-repo session then analyzes just the diff."""
    init()
    due = ["analyzed_at IS NULL", "status = 'error'"]
    if rescan:
        due.append("(pushed_at IS NOT NULL AND "
                   "(analyzed_pushed_at IS NULL OR pushed_at != analyzed_pushed_at))")
    q = [
        "SELECT * FROM targets",
        "WHERE status != 'skipped'",
        "  AND (" + " OR ".join(due) + ")",
    ]
    vals: list = []
    if pushed_since:
        q.append("  AND pushed_at >= ?")
        vals.append(pushed_since)
    q.append("ORDER BY pushed_at DESC LIMIT ?")
    vals.append(count)
    with _connect() as c:
        return [dict(r) for r in c.execute("\n".join(q), tuple(vals)).fetchall()]


def pending_count(pushed_since: str | None = None, rescan: bool = False) -> int:
    return len(next_batch(count=10_000_000, pushed_since=pushed_since, rescan=rescan))


def owners() -> list[str]:
    """Distinct repo owners (orgs/users) currently tracked — drives `--rescan`
    re-syncs when no explicit --org/--user is given."""
    init()
    with _connect() as c:
        rows = c.execute("SELECT DISTINCT org FROM targets WHERE org IS NOT NULL "
                         "AND org != '' ORDER BY org").fetchall()
        return [r["org"] for r in rows]


# --- Findings mirror --------------------------------------------------------

def sync_finding(slug: str, commit_sha: str | None, f: dict) -> None:
    """Upsert one finding (from a target's findings.json) into the DB."""
    fid = f.get("id")
    if not fid:
        return
    init()
    with _connect() as c:
        exists = c.execute("SELECT id FROM findings WHERE id=?", (fid,)).fetchone()
        vals = {
            "slug": slug,
            "commit_sha": commit_sha or f.get("last_commit"),
            "severity": (f.get("severity") or "").upper(),
            "category": f.get("category"),
            "title": f.get("title"),
            "file": f.get("file"),
            "line": f.get("line"),
            "cwe": json.dumps(f.get("cwe") or []),
            "entrypoint": f.get("entrypoint"),
            "reachability": f.get("reachability"),
            "poc": f.get("poc"),
            "evidence": f.get("evidence"),
            "status": f.get("status"),
            "verdict": f.get("verdict"),
            "reported": 1 if f.get("reported") else 0,
            "fix_reported": 1 if f.get("fix_reported") else 0,
            "last_seen": now_iso(),
            "updated": now_iso(),
        }
        if exists:
            sets = ", ".join(f"{k}=?" for k in vals)
            c.execute(f"UPDATE findings SET {sets} WHERE id=?", (*vals.values(), fid))
        else:
            vals["id"] = fid
            vals["first_seen"] = now_iso()
            cols = ", ".join(vals)
            qs = ", ".join("?" for _ in vals)
            c.execute(f"INSERT INTO findings ({cols}) VALUES ({qs})", tuple(vals.values()))
        # refresh this target's severity counts
        def _n(sev):
            return c.execute("SELECT COUNT(*) FROM findings WHERE slug=? AND severity=?",
                             (slug, sev)).fetchone()[0]
        c.execute("UPDATE targets SET medium_count=?, high_count=?, critical_count=? WHERE slug=?",
                  (_n("MEDIUM"), _n("HIGH"), _n("CRITICAL"), slug))


def query_findings(slug: str | None = None, min_sev: str | None = None,
                   status: str | None = None, limit: int | None = None) -> list[dict]:
    init()
    q = "SELECT * FROM findings"
    where, vals = [], []
    if slug:
        where.append("slug=?"); vals.append(slug)
    if status:
        where.append("status=?"); vals.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    with _connect() as c:
        rows = [dict(r) for r in c.execute(q, tuple(vals)).fetchall()]
    if min_sev:
        floor = sev_rank(min_sev)
        rows = [r for r in rows if sev_rank(r.get("severity")) >= floor]
    rows.sort(key=lambda r: sev_rank(r.get("severity")), reverse=True)
    return rows[:limit] if limit else rows


def summary() -> dict:
    init()
    with _connect() as c:
        by_status = {r["status"]: r["n"] for r in
                     c.execute("SELECT status, COUNT(*) n FROM targets GROUP BY status")}
        totals = {
            "targets": c.execute("SELECT COUNT(*) FROM targets").fetchone()[0],
            "analyzed": c.execute("SELECT COUNT(*) FROM targets WHERE status='analyzed'").fetchone()[0],
            "findings": c.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "critical": c.execute("SELECT COUNT(*) FROM findings WHERE severity='CRITICAL'").fetchone()[0],
            "high": c.execute("SELECT COUNT(*) FROM findings WHERE severity='HIGH'").fetchone()[0],
            "medium": c.execute("SELECT COUNT(*) FROM findings WHERE severity='MEDIUM'").fetchone()[0],
            "verified": c.execute("SELECT COUNT(*) FROM findings WHERE status='verified'").fetchone()[0],
        }
    return {"db": str(DB_PATH), "targets_by_status": by_status, **totals}


# --- CLI --------------------------------------------------------------------

def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main() -> None:
    ap = argparse.ArgumentParser(prog="orgdb", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init")
    sub.add_parser("summary")
    p = sub.add_parser("add"); p.add_argument("--repo", required=True)
    p = sub.add_parser("remove"); p.add_argument("--slug", required=True)
    p = sub.add_parser("targets"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("findings"); p.add_argument("--slug"); p.add_argument("--min-sev"); p.add_argument("--status"); p.add_argument("--limit", type=int, default=50)
    p = sub.add_parser("next-batch"); p.add_argument("--count", type=int, default=10)
    p.add_argument("--pushed-since"); p.add_argument("--rescan", action="store_true")
    p = sub.add_parser("pending"); p.add_argument("--pushed-since"); p.add_argument("--rescan", action="store_true")
    sub.add_parser("owners")
    p = sub.add_parser("show"); p.add_argument("--slug", required=True)
    p = sub.add_parser("set-status"); p.add_argument("--slug", required=True)
    p.add_argument("--status", required=True); p.add_argument("--error"); p.add_argument("--analyzed-commit")
    p = sub.add_parser("reap-stale"); p.add_argument("--max-attempts", type=int, default=2)
    args = ap.parse_args()

    if args.cmd == "init":
        _print(init())
    elif args.cmd == "summary":
        _print(summary())
    elif args.cmd == "add":
        slug = upsert_target({"repo_url": args.repo})
        _print(get(slug))
    elif args.cmd == "remove":
        init()
        with _connect() as c:
            c.execute("DELETE FROM findings WHERE slug=?", (args.slug,))
            c.execute("DELETE FROM targets WHERE slug=?", (args.slug,))
        _print({"removed": args.slug})
    elif args.cmd == "targets":
        init()
        with _connect() as c:
            q = ("SELECT slug,name,default_branch,pushed_at,status,analyzed_commit,"
                 "medium_count,high_count,critical_count FROM targets")
            vals = []
            if args.status:
                q += " WHERE status=?"; vals.append(args.status)
            q += " ORDER BY pushed_at DESC LIMIT ?"; vals.append(args.limit)
            _print([dict(r) for r in c.execute(q, tuple(vals)).fetchall()])
    elif args.cmd == "findings":
        _print(query_findings(args.slug, args.min_sev, args.status, args.limit))
    elif args.cmd == "next-batch":
        _print(next_batch(args.count, args.pushed_since, rescan=args.rescan))
    elif args.cmd == "pending":
        _print({"pending": pending_count(args.pushed_since, rescan=args.rescan)})
    elif args.cmd == "owners":
        _print({"owners": owners()})
    elif args.cmd == "show":
        t = get(args.slug)
        if not t:
            raise SystemExit(f"unknown target: {args.slug}")
        t["findings"] = query_findings(args.slug)
        _print(t)
    elif args.cmd == "set-status":
        set_status(args.slug, args.status, error=args.error, analyzed_commit=args.analyzed_commit)
        _print(get(args.slug))
    elif args.cmd == "reap-stale":
        _print(reap_stale(args.max_attempts))


if __name__ == "__main__":
    main()
