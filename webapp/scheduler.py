"""Continuous-scan scheduler — one cron trigger per enabled repo.

Each repo carries a crontab string (e.g. "0 3 * * *" = daily 03:00). We register a
CronTrigger per repo that simply enqueues a scan; the runner serializes execution.
Call reload() whenever repos change.
"""
from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

import db
import runner

_sched = BackgroundScheduler(timezone="UTC")


def _fire(repo_id: int) -> None:
    repo = db.get_repo(repo_id)
    if repo and repo.get("enabled"):
        runner.enqueue(repo_id, trigger="schedule")


def reload() -> dict:
    """Rebuild the schedule from the DB. Returns {slug: next_run_iso}."""
    _sched.remove_all_jobs()
    out: dict = {}
    for r in db.list_repos():
        cron = (r.get("cron") or "").strip()
        if not (r.get("enabled") and cron):
            continue
        try:
            trig = CronTrigger.from_crontab(cron, timezone="UTC")
        except (ValueError, TypeError):
            out[r["slug"]] = "invalid cron"
            continue
        job = _sched.add_job(_fire, trig, args=[r["id"]], id=f"repo-{r['id']}",
                             replace_existing=True, misfire_grace_time=3600,
                             coalesce=True, max_instances=1)
        nxt = job.next_run_time
        out[r["slug"]] = nxt.isoformat() if nxt else None
    return out


def next_runs() -> dict:
    out = {}
    for job in _sched.get_jobs():
        out[job.id] = job.next_run_time.isoformat() if job.next_run_time else None
    return out


def start() -> None:
    if not _sched.running:
        _sched.start()
    reload()
