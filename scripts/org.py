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
import base64
import json
import os
import re
import subprocess
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

UA = "security-forge/1.0"
_GH_COM = {"github.com", "www.github.com", "api.github.com"}


def _parse_owner(raw: str) -> tuple[str, str]:
    """Split a --org/--user value into (host, owner). Accepts a bare name, a
    'host/owner' key, or a full URL (with optional trailing path / .git).

    'my-org'                                  -> ('github.com', 'my-org')
    'github.example.com/my-org'               -> ('github.example.com', 'my-org')
    'https://github.example.com/my-org/'      -> ('github.example.com', 'my-org')
    'https://github.example.com/my-org/x.git' -> ('github.example.com', 'my-org')
    """
    s = (raw or "").strip()
    if "://" in s:                       # strip scheme
        s = s.split("://", 1)[1]
    if "@" in s and "/" not in s.split("@", 1)[0]:   # strip user:pass@ / git@
        s = s.split("@", 1)[1]
    s = s.strip("/")
    parts = [p for p in s.replace("\\", "/").split("/") if p]
    if not parts:
        return "github.com", ""
    # A first segment that looks like a host (has a dot or :port) means the
    # value is host-qualified; otherwise the whole thing is a github.com owner.
    if ("." in parts[0] or ":" in parts[0]) and len(parts) >= 2:
        return parts[0], parts[1]
    return "github.com", parts[0]


def _api_base(host: str) -> str:
    """REST API root for a host. Enterprise Server lives at /api/v3; an explicit
    GITHUB_API_URL overrides everything for non-.com hosts."""
    host = (host or "github.com").strip().strip("/")
    if host in _GH_COM:
        return "https://api.github.com"
    ov = (os.environ.get("GITHUB_API_URL") or "").strip()
    if ov:
        return ov.rstrip("/")
    return f"https://{host}/api/v3"


def owner_key(host: str, owner: str) -> str:
    """Durable owner key stored per repo. Bare login on github.com (backward
    compatible); host-qualified elsewhere so --rescan can re-target the host."""
    return owner if host in _GH_COM else f"{host}/{owner}"


def _token_for_env(host: str) -> str:
    """Explicit token from the environment/.env. A host-specific var wins, then
    the generic enterprise token, then the classic GITHUB_TOKEN/GH_TOKEN."""
    load_env()
    cands = ["GITHUB_TOKEN_" + re.sub(r"[^A-Za-z0-9]", "_", host).upper()]
    if host not in _GH_COM:
        cands += ["GHE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"]
    cands += ["GITHUB_TOKEN", "GH_TOKEN"]
    for name in cands:
        v = (os.environ.get(name) or "").strip()
        if v:
            return v
    return ""


def _gh_cli_token(host: str) -> str:
    """Token from an authenticated `gh` CLI, if it's installed for this host."""
    try:
        r = subprocess.run(["gh", "auth", "token", "--hostname", host],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            return (r.stdout or "").strip()
    except Exception:  # noqa: BLE001  (gh absent / any failure -> no token)
        pass
    return ""


def _git_credential(host: str) -> tuple[str, str] | None:
    """Ask git's credential helper for the stored (username, password) for this
    host — the SAME creds `git clone` uses, so org listing works wherever a
    single-repo clone already does. Never prompts (fails fast if nothing stored)."""
    try:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}
        r = subprocess.run(["git", "credential", "fill"],
                           input=f"protocol=https\nhost={host}\n\n",
                           capture_output=True, text=True, timeout=10, env=env)
        if r.returncode != 0:
            return None
        d = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        if d.get("password"):
            return d.get("username") or "x-access-token", d["password"]
    except Exception:  # noqa: BLE001
        pass
    return None


def _auth_header(host: str) -> str:
    """Resolve an Authorization header value: an explicit env/`gh` token becomes
    a Bearer; otherwise fall back to the git credential store as Basic auth (what
    `git clone` itself sends). Empty string => send the request unauthenticated."""
    tok = _token_for_env(host) or _gh_cli_token(host)
    if tok:
        return f"Bearer {tok}"
    cred = _git_credential(host)
    if cred:
        blob = base64.b64encode(f"{cred[0]}:{cred[1]}".encode()).decode()
        return f"Basic {blob}"
    return ""


def _headers(host: str) -> dict:
    h = {"User-Agent": UA, "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28"}
    auth = _auth_header(host)
    if auth:
        h["Authorization"] = auth
    return h


def _get(url: str, host: str, timeout: int = 30):
    req = urllib.request.Request(url, headers=_headers(host))
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace")), resp.headers


def _list_repos(owner: str, is_user: bool, host: str = "github.com") -> list[dict]:
    """Page through every repo for an org (or user) on `host`. Newest-push first."""
    api = _api_base(host)
    kind = "users" if is_user else "orgs"
    out: list[dict] = []
    page = 1
    while True:
        url = (f"{api}/{kind}/{owner}/repos?per_page=100&page={page}"
               f"&type=all&sort=pushed&direction=desc")
        try:
            data, _ = _get(url, host)
        except urllib.error.HTTPError as e:
            if e.code == 404 and not is_user:
                # not an org — retry as a user account
                eprint(f"[org] '{owner}' is not an org on {host}, retrying as a user…")
                return _list_repos(owner, is_user=True, host=host)
            eprint(f"[org] GitHub API error {e.code} on page {page} ({api}): {e.reason}")
            break
        except Exception as e:  # noqa: BLE001
            eprint(f"[org] list page {page} failed ({api}): {e}")
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
    """List all repos for an org/user and upsert them into the DB queue. `owner`
    may be a bare name, a 'host/owner' key, or a full org/user URL — the host is
    derived so GitHub Enterprise Server orgs work the same as github.com."""
    host, owner = _parse_owner(owner)
    okey = owner_key(host, owner)
    orgdb.init()
    repos = _list_repos(owner, is_user, host)
    added, skipped = 0, 0
    sk_fork = sk_arch = sk_size = 0
    for r in repos:
        if not include_forks and r.get("fork"):
            skipped += 1; sk_fork += 1; continue
        if not include_archived and r.get("archived"):   # archived skipped by default
            skipped += 1; sk_arch += 1; continue
        if int(r.get("size") or 0) < min_size_kb:
            skipped += 1; sk_size += 1; continue
        orgdb.upsert_target({
            "repo_url": r.get("clone_url") or r.get("html_url"),
            "name": r.get("full_name"),
            "org": okey,
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
    return {"owner": okey, "host": host, "kind": "user" if is_user else "org",
            "listed": len(repos), "queued": added, "filtered_out": skipped,
            "skipped_archived": sk_arch, "skipped_forks": sk_fork,
            "skipped_small": sk_size, "pending": orgdb.pending_count()}


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
