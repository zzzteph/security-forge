"""security-forge — GitHub org/user repo catalog + per-repo record.

The queue source. Instead of a wordpress-style catalog, this lists every repo in
a GitHub org (or user) through the GitHub REST API and upserts them into the
durable DB (scripts/orgdb.py) as analysis targets. The orchestrator then drains
that queue one repo at a time. `record` is the mirror step a per-repo session
runs at the end: it folds that repo's findings.json into the DB and marks it
analyzed at the current commit.

Auth: set GITHUB_TOKEN in .env (or the environment) for private repos and higher
rate limits. Public orgs work unauthenticated (rate-limited).

Per repo, state is keyed exactly like the rest of the pipeline: the repo's clone
URL drives common.target_slug() -> "github.com/owner/repo" which keys target/,
state/, knowledge/, and the DB row.

CLI:
    python scripts/org.py sync --org <org>            # list all repos -> DB queue
    python scripts/org.py sync --user <name>          # a user account instead of an org
    python scripts/org.py add  --repo <url>           # enqueue a single repo
    python scripts/org.py pending
    python scripts/org.py next-batch [--count 10]
    python scripts/org.py record --repo <url>         # findings.json -> DB, mark analyzed
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


# --- bootstrap per-repo keying BEFORE importing common ----------------------
# common.py resolves per-target paths from SECFORGE_TARGET_REPO at import time.
# If we were handed a --repo/--slug, set that env first so target/state/knowledge
# (and the store the workflow wrote) all key to this repo.
def _argv_val(flag: str) -> str | None:
    for i, a in enumerate(sys.argv):
        if a == flag and i + 1 < len(sys.argv):
            return sys.argv[i + 1].strip()
        if a.startswith(flag + "="):
            return a.split("=", 1)[1].strip()
    return None


_REPO_ARG = _argv_val("--repo")
_SLUG_ARG = _argv_val("--slug")
if _REPO_ARG:
    os.environ.setdefault("SECFORGE_TARGET_REPO", _REPO_ARG)
elif _SLUG_ARG:
    os.environ.setdefault("SECFORGE_TARGET", _SLUG_ARG)

sys.path.insert(0, str(Path(__file__).resolve().parent))
import orgdb  # noqa: E402
import repo as repomod  # noqa: E402  (reuse current_commit)
from common import load_env, target_slug, eprint, now_iso, configure_stdio  # noqa: E402

configure_stdio()

API = "https://api.github.com"
UA = "security-forge/1.0"


def _headers() -> dict:
    load_env()
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    tok = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get(url: str, timeout: int = 30):
    req = urllib.request.Request(url, headers=_headers())
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace")), resp.headers


def _list_repos(owner: str, is_user: bool) -> list[dict]:
    """Page through every repo for an org (or user). Newest-push first."""
    kind = "users" if is_user else "orgs"
    out: list[dict] = []
    page = 1
    while True:
        url = (f"{API}/{kind}/{owner}/repos?per_page=100&page={page}"
               f"&type=all&sort=pushed&direction=desc")
        try:
            data, _ = _get(url)
        except urllib.error.HTTPError as e:
            if e.code == 404 and not is_user:
                # not an org — retry as a user account
                eprint(f"[org] '{owner}' is not an org, retrying as a user…")
                return _list_repos(owner, is_user=True)
            eprint(f"[org] GitHub API error {e.code} on page {page}: {e.reason}")
            break
        except Exception as e:  # noqa: BLE001
            eprint(f"[org] list page {page} failed: {e}")
            break
        if not isinstance(data, list) or not data:
            break
        out.extend(data)
        if len(data) < 100:
            break
        page += 1
    return out


def sync(owner: str, is_user: bool = False, include_forks: bool = False,
         include_archived: bool = False, min_size_kb: int = 0) -> dict:
    """List all repos for an org/user and upsert them into the DB queue."""
    orgdb.init()
    repos = _list_repos(owner, is_user)
    added, skipped = 0, 0
    for r in repos:
        if not include_forks and r.get("fork"):
            skipped += 1; continue
        if not include_archived and r.get("archived"):
            skipped += 1; continue
        if int(r.get("size") or 0) < min_size_kb:
            skipped += 1; continue
        orgdb.upsert_target({
            "repo_url": r.get("clone_url") or r.get("html_url"),
            "name": r.get("full_name"),
            "org": (r.get("owner") or {}).get("login"),
            "default_branch": r.get("default_branch"),
            "pushed_at": r.get("pushed_at"),
            "size": r.get("size"),
            "private": r.get("private"),
            "archived": r.get("archived"),
            "fork": r.get("fork"),
            "language": r.get("language"),
            "description": r.get("description"),
            "homepage": r.get("homepage"),
        })
        added += 1
    return {"owner": owner, "kind": "user" if is_user else "org",
            "listed": len(repos), "queued": added, "filtered_out": skipped,
            "pending": orgdb.pending_count()}


def record(repo_url: str | None, slug: str | None) -> dict:
    """After a session: mirror this repo's findings.json into the DB and mark it
    analyzed at the current commit."""
    import store  # noqa: E402  (keyed to this repo via env)
    if not slug:
        slug = target_slug(repo_url or os.environ.get("SECFORGE_TARGET_REPO", ""))
    if repo_url:
        orgdb.upsert_target({"repo_url": repo_url})
    commit = repomod.current_commit()
    findings = store.query()   # all findings for this repo (from the JSON store)
    for f in findings:
        orgdb.sync_finding(slug, commit or f.get("last_commit"), f)
    counts = {s: sum(1 for f in findings if (f.get("severity") or "").upper() == s)
              for s in ("MEDIUM", "HIGH", "CRITICAL")}
    orgdb.set_status(slug, "analyzed", analyzed_commit=commit)
    return {"slug": slug, "analyzed_commit": commit,
            "findings_synced": len(findings), **{k.lower(): v for k, v in counts.items()}}


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def main() -> None:
    ap = argparse.ArgumentParser(prog="org", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sync")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--org"); g.add_argument("--user")
    p.add_argument("--include-forks", action="store_true")
    p.add_argument("--include-archived", action="store_true")
    p.add_argument("--min-size-kb", type=int, default=0)

    p = sub.add_parser("add"); p.add_argument("--repo", required=True)
    p = sub.add_parser("pending")
    p = sub.add_parser("next-batch"); p.add_argument("--count", type=int, default=10)
    p = sub.add_parser("record")
    p.add_argument("--repo"); p.add_argument("--slug")

    args = ap.parse_args()
    if args.cmd == "sync":
        owner = args.org or args.user
        _print(sync(owner, is_user=bool(args.user),
                    include_forks=args.include_forks,
                    include_archived=args.include_archived,
                    min_size_kb=args.min_size_kb))
    elif args.cmd == "add":
        slug = orgdb.upsert_target({"repo_url": args.repo})
        _print(orgdb.get(slug))
    elif args.cmd == "pending":
        _print({"pending": orgdb.pending_count()})
    elif args.cmd == "next-batch":
        _print(orgdb.next_batch(args.count))
    elif args.cmd == "record":
        if not (args.repo or args.slug):
            raise SystemExit("record needs --repo <url> or --slug <slug>")
        _print(record(args.repo, args.slug))


if __name__ == "__main__":
    main()
