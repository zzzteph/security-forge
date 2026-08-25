"""Persistent findings store (survives across cycles).

A "finding" is a dict. The store lives in state/findings.json keyed by a stable
id so the same issue is not re-reported every cycle. The agentic layer (the
skill + subagents) reads/writes findings through the pipeline CLI, so this is
the single source of truth for what has been seen, verified, and reported.

Finding lifecycle (status):
    new -> triaged -> verifying -> verified | dismissed
                                        |
                                        +-> fixed   (mitigation confirmed on a later run)
    'reported' (first announced) and 'fix_reported' (mitigation announced) are
    tracked separately so each is announced locally exactly once.

The store lives in the durable knowledge dir (knowledge/<target>/findings.json)
so it persists with the project model across runs (committed to the model
branch), not in the ephemeral state/ scratch.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import KNOWLEDGE_DIR, now_iso, sev_rank  # noqa: E402

FINDINGS = KNOWLEDGE_DIR / "findings.json"

VALID_STATUS = {"new", "triaged", "verifying", "verified", "dismissed", "fixed"}


def _load() -> dict:
    if FINDINGS.exists():
        try:
            return json.loads(FINDINGS.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _save(db: dict) -> None:
    FINDINGS.parent.mkdir(parents=True, exist_ok=True)
    FINDINGS.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")


def upsert(findings: list[dict], commit: str | None) -> list[dict]:
    """Insert new findings, refresh last_seen on known ones. Returns the new ones."""
    db = _load()
    added: list[dict] = []
    for f in findings:
        fid = f.get("id")
        if not fid:
            continue
        if fid in db:
            db[fid]["last_seen"] = now_iso()
            if commit:
                db[fid]["last_commit"] = commit
        else:
            f.setdefault("status", "new")
            f["reported"] = False
            f["first_seen"] = now_iso()
            f["last_seen"] = now_iso()
            f["first_commit"] = commit
            f["last_commit"] = commit
            db[fid] = f
            added.append(f)
    _save(db)
    return added


def add_one(finding: dict, commit: str | None = None) -> dict:
    """Insert a single agent-discovered finding (returns the stored record)."""
    added = upsert([finding], commit)
    return added[0] if added else _load().get(finding.get("id"), finding)


def set_status(fid: str, status: str, note: str | None = None,
               evidence: str | None = None, reported: bool | None = None,
               fix_reported: bool | None = None, poc_verified: bool | None = None,
               poc_evidence: str | None = None, poc_dir: str | None = None,
               advisory_path: str | None = None) -> dict:
    db = _load()
    if fid not in db:
        raise SystemExit(f"unknown finding id: {fid}")
    if status and status not in VALID_STATUS:
        raise SystemExit(f"invalid status '{status}'. one of: {sorted(VALID_STATUS)}")
    rec = db[fid]
    if status:
        rec["status"] = status
    if reported is not None:
        rec["reported"] = reported
        if reported:
            rec["reported_at"] = now_iso()
    if fix_reported is not None:              # mitigation announced exactly once
        rec["fix_reported"] = fix_reported
        if fix_reported:
            rec["fix_reported_at"] = now_iso()
    if poc_verified is not None:
        # The HARD gate for an advisory: True only when the runnable PoC BUNDLE
        # itself reproduced (exit 0 / EXPLOITED) this cycle — set exclusively by
        # `pipeline.py verify-poc`, never by hand. A later failed re-check flips it
        # back to False, which strips the advisory in `gc-advisories`.
        rec["poc_verified"] = bool(poc_verified)
        rec["poc_verified_at"] = now_iso() if poc_verified else None
    if poc_evidence:
        rec["poc_evidence"] = poc_evidence
    if poc_dir:
        rec["poc_dir"] = poc_dir
    if advisory_path:
        rec["advisory_path"] = advisory_path
    if evidence:
        rec["evidence"] = evidence
    if note:
        rec.setdefault("notes", []).append({"ts": now_iso(), "note": note})
    rec["updated"] = now_iso()
    _save(db)
    return rec


def get(fid: str) -> dict | None:
    return _load().get(fid)


def query(status: str | None = None, min_sev: str | None = None,
          reported: bool | None = None, limit: int | None = None) -> list[dict]:
    items = list(_load().values())
    if status:
        items = [f for f in items if f.get("status") == status]
    if reported is not None:
        items = [f for f in items if bool(f.get("reported")) == reported]
    if min_sev:
        floor = sev_rank(min_sev)
        items = [f for f in items if sev_rank(f.get("severity", "UNKNOWN")) >= floor]
    items.sort(key=lambda f: sev_rank(f.get("severity", "UNKNOWN")), reverse=True)
    if limit:
        items = items[:limit]
    return items


def counts() -> dict:
    db = _load()
    by_status: dict = {}
    by_sev: dict = {}
    for f in db.values():
        by_status[f.get("status", "?")] = by_status.get(f.get("status", "?"), 0) + 1
        by_sev[f.get("severity", "?")] = by_sev.get(f.get("severity", "?"), 0) + 1
    return {"total": len(db), "by_status": by_status, "by_severity": by_sev}
