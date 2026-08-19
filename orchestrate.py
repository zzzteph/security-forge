#!/usr/bin/env python3
"""security-forge — per-repo orchestrator (scan a whole GitHub org, reliably).

Runs a DEDICATED headless Claude session for EACH repo, one at a time, with a
hard per-repo wall-clock timeout. Whatever a single session does — finishes,
stalls, gets killed by a platform safeguard, errors, or refuses — the orchestrator
kills it at the deadline, tears down the sandbox, records the outcome in the
durable DB, and moves on to the NEXT repo. It never stops for one repo.

Why this is reliable: the orchestrator is a plain subprocess manager that holds
*no model context*, so it can drain an entire org that no single Claude session
could. Each repo gets a fresh session that sees only that one repo — context
exhaustion, cross-repo bleed, and "it stopped after N" all go away. Failures are
bounded and isolated per repo, and every result lands in db/security-forge.db.

Usage:
  python orchestrate.py --repo https://github.com/owner/repo   # just ONE repo, then stop
  python orchestrate.py --org my-org            # sync the org, then drain it
  python orchestrate.py --user my-handle        # a user account instead of an org
  python orchestrate.py                          # drain whatever is already queued
  python orchestrate.py --org my-org --rescan    # re-analyze only the repos that changed
  python orchestrate.py --org my-org --dry-run   # show the plan, launch nothing

Each repo's session logs to logs/orch-<slug>-<ts>.log. Fully resumable: the DB
tracks analyzed/error/skipped, so re-running continues from what's left.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PY = sys.executable or "python"


def _helper_json(script: str, *args):
    """Run an orgdb.py subcommand and parse its JSON stdout (or None)."""
    r = subprocess.run([PY, str(ROOT / "scripts" / script), *args],
                       cwd=str(ROOT), capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    try:
        return json.loads(r.stdout)
    except Exception:
        return None


def orgdb(*a):
    return _helper_json("orgdb.py", *a)


def org(*a):
    return _helper_json("org.py", *a)


def pending_count(rescan: bool = False) -> int:
    a = ["pending"] + (["--rescan"] if rescan else [])
    return int((orgdb(*a) or {}).get("pending", 0))


def next_targets(count: int, rescan: bool = False) -> list:
    a = ["next-batch", "--count", str(count)] + (["--rescan"] if rescan else [])
    r = orgdb(*a)
    return [t for t in r if t.get("slug")] if isinstance(r, list) else []


def build_prompt(repo_url: str, slug: str) -> str:
    return (
        f"You are analyzing EXACTLY ONE repository: {repo_url} (slug {slug}). "
        f"SECFORGE_TARGET_REPO is already set to it in your environment, so every "
        f"`python scripts/...` call keys to this repo. Follow opt/workflow.md end "
        f"to end for THIS repo only: run `python scripts/pipeline.py prep`, build/"
        f"refresh its model in knowledge/, hunt for real MEDIUM/HIGH/CRITICAL bugs, "
        f"verify every candidate in the container sandbox, write an advisory + "
        f"runnable PoC for each verified finding, then run "
        f"`python scripts/org.py record --repo {repo_url}` to fold the findings "
        f"into the DB and mark it analyzed, and finally `python scripts/verify.py "
        f"nuke`. Do NOT analyze any other repo, do NOT loop to a next repo, never "
        f"ask questions, keep everything local (notify-only). Stop as soon as this "
        f"one repo is recorded."
    )


def _kill_tree(p: subprocess.Popen):
    """Hard-kill the session and any children (docker/podman etc.) it spawned."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    except Exception:
        pass
    try:
        p.wait(timeout=30)
    except Exception:
        pass


def _tail(path: Path, nbytes: int = 4096) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - nbytes))
            chunk = f.read().decode("utf-8", "replace")
        lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
        return lines[-1][:100] if lines else "(starting…)"
    except Exception:
        return ""


def run_session(prompt: str, env_extra: dict, claude: str, model: str,
                timeout: int, log_path: Path, heartbeat: int = 30) -> int:
    """Launch one headless Claude session, bounded by a hard timeout. Prints a
    heartbeat every `heartbeat`s. Returns the exit code, or 124 if killed at the
    deadline. Never raises (except a missing `claude` binary)."""
    cmd = [claude, "-p", prompt, "--verbose", "--dangerously-skip-permissions"]
    if model:
        cmd += ["--model", model]
    env = {**os.environ, **env_extra}
    popen_kw = {}
    if os.name == "posix":
        popen_kw["start_new_session"] = True
    else:
        popen_kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    log = open(log_path, "w", encoding="utf-8", errors="replace")
    try:
        p = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log,
                             stderr=subprocess.STDOUT, env=env, **popen_kw)
    except FileNotFoundError:
        log.close()
        print(f"[orch] FATAL: '{claude}' not found — install Claude Code or pass "
              f"--claude <path>.", file=sys.stderr)
        raise SystemExit(2)
    start = time.monotonic()
    try:
        while True:
            remaining = timeout - (time.monotonic() - start)
            if remaining <= 0:
                _kill_tree(p)
                return 124
            try:
                return p.wait(timeout=min(heartbeat, remaining))
            except subprocess.TimeoutExpired:
                el = int(time.monotonic() - start)
                print(f"[orch]     .. {el // 60}m{el % 60:02d}s  {_tail(log_path)}", flush=True)
    finally:
        log.close()


def data_root() -> Path:
    return Path(os.environ.get("SECFORGE_DATA_DIR") or ROOT).expanduser().resolve()


def process_repo(t: dict, args, logs: Path, idx: int, total) -> str:
    """Run one bounded session for a single repo, tear down, and return its final
    DB status. Shared by the org-drain loop and the single --repo path."""
    slug = t["slug"]
    repo_url = t.get("repo_url") or f"https://{slug}"
    ts = time.strftime("%Y%m%d-%H%M%S")
    log = logs / f"orch-{slug.replace('/', '-')}-{ts}.log"
    env_extra = {"SECFORGE_TARGET_REPO": repo_url, "SECFORGE_TARGET": slug}
    if os.environ.get("SECFORGE_DATA_DIR"):
        env_extra["SECFORGE_DATA_DIR"] = os.environ["SECFORGE_DATA_DIR"]
    orgdb("set-status", "--slug", slug, "--status", "analyzing")
    print(f"[orch] ({idx}/{total}) {slug} → session (≤{args.timeout}s)  log: {log}",
          flush=True)
    t0 = time.monotonic()
    rc = run_session(build_prompt(repo_url, slug), env_extra, args.claude,
                     args.model, args.timeout, log, args.heartbeat)
    cleanup(slug, env_extra)
    orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
    row = orgdb("show", "--slug", slug) or {}
    st = row.get("status")
    dt = int(time.monotonic() - t0)
    if st == "analyzed":
        print(f"[orch]   ✓ analyzed {(row.get('analyzed_commit') or '')[:8]} "
              f"(rc={rc}, {dt}s, MED={row.get('medium_count',0)} "
              f"HIGH={row.get('high_count',0)} CRIT={row.get('critical_count',0)})")
    elif st == "skipped":
        print(f"[orch]   ⤼ skipped after repeated aborts (rc={rc}, {dt}s)")
    else:
        print(f"[orch]   ✗ not completed (status={st}, rc={rc}, {dt}s) — retry next run")
    return st


def cleanup(slug: str, env_extra: dict):
    """Guarantee teardown after every session: nuke the sandbox and wipe this
    repo's disposable clone + scratch so the next repo starts clean, even on a
    kill. knowledge/ (the durable model) and the DB are kept."""
    subprocess.run([PY, str(ROOT / "scripts" / "verify.py"), "nuke"],
                   cwd=str(ROOT), capture_output=True, text=True,
                   env={**os.environ, **env_extra})
    import shutil
    data = data_root()
    for sub in ("target", "state"):
        try:
            shutil.rmtree(data / sub / slug, ignore_errors=True)
        except Exception:
            pass


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--org", help="GitHub org to sync into the queue before draining")
    g.add_argument("--user", help="GitHub user account instead of an org")
    g.add_argument("--repo", help="analyze a SINGLE repo URL (one session), then stop")
    ap.add_argument("--include-forks", action="store_true")
    ap.add_argument("--include-archived", action="store_true")
    ap.add_argument("--timeout", type=int, default=1800,
                    help="hard per-repo session timeout, seconds (default: 1800)")
    ap.add_argument("--max-repos", type=int, default=0,
                    help="stop after N repos this run (0 = until the queue is empty)")
    ap.add_argument("--max-attempts", type=int, default=2,
                    help="skip a repo after this many aborted sessions across runs")
    ap.add_argument("--claude", default=os.environ.get("CLAUDE_BIN", "claude"),
                    help="path to the Claude Code CLI (default: claude)")
    ap.add_argument("--model", default="", help="optional --model to pass through")
    ap.add_argument("--heartbeat", type=int, default=30,
                    help="seconds between progress heartbeats (default: 30)")
    ap.add_argument("--output-dir", default="",
                    help="folder for ALL artifacts (db, logs, knowledge, target, "
                         "state). Defaults to the repo folder; set this to keep "
                         "results out of the hidden ~/.claude/plugins cache. Sets "
                         "SECFORGE_DATA_DIR for every session it launches.")
    ap.add_argument("--no-sync", action="store_true",
                    help="skip the org sync (drain the DB as-is)")
    ap.add_argument("--rescan", action="store_true",
                    help="re-sync and re-queue already-analyzed repos whose upstream "
                         "changed since last analysis, then re-analyze just the diffs")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and launch nothing")
    args = ap.parse_args()

    # Redirect all artifacts before anything touches the DB; children inherit it.
    if args.output_dir:
        os.environ["SECFORGE_DATA_DIR"] = str(Path(args.output_dir).expanduser().resolve())
    data = data_root()
    logs = data / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    print(f"[orch] artifacts -> {data}")

    orgdb("init")

    # Single-repo mode: enqueue the one repo and run exactly one session, then stop.
    if args.repo:
        if not args.dry_run:
            orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
        row = orgdb("add", "--repo", args.repo) or {"slug": args.repo, "repo_url": args.repo}
        slug = row.get("slug") or args.repo
        if args.dry_run:
            print(f"[orch] (1) would analyze single repo {slug}")
            return
        print(f"[orch] single-repo mode; heartbeat every {args.heartbeat}s; "
              f"tail -f {logs}/orch-*.log", flush=True)
        st = process_repo(row, args, logs, 1, 1)
        print(f"\n[orch] done. {slug} -> {st}")
        return

    extra = (["--include-forks"] if args.include_forks else []) + \
            (["--include-archived"] if args.include_archived else [])
    if not args.dry_run:
        orgdb("reap-stale", "--max-attempts", str(args.max_attempts))
        if (args.org or args.user) and not args.no_sync:
            who = ["--org", args.org] if args.org else ["--user", args.user]
            s = org("sync", *who, *extra) or {}
            print(f"[orch] synced {s.get('kind','?')} {args.org or args.user}: "
                  f"listed={s.get('listed','?')} queued={s.get('queued','?')} "
                  f"filtered_out={s.get('filtered_out','?')}")
        elif args.rescan and not args.no_sync:
            # rescan without an explicit owner: refresh every owner we already track
            for owner in (orgdb("owners") or {}).get("owners", []):
                s = org("sync", "--org", owner, *extra) or {}
                print(f"[orch] re-synced {owner}: listed={s.get('listed','?')} "
                      f"queued={s.get('queued','?')}")

    total = pending_count(rescan=args.rescan)
    mode = "rescan (new + changed)" if args.rescan else "sweep (new only)"
    print(f"[orch] mode={mode} pending={total} timeout={args.timeout}s"
          f"{' (DRY-RUN)' if args.dry_run else ''}")
    if not args.dry_run:
        print(f"[orch] heartbeat every {args.heartbeat}s; watch a session live with:  "
              f"tail -f {logs}/orch-*.log", flush=True)

    attempted, analyzed, errored, skipped, n = set(), 0, 0, 0, 0
    while True:
        if args.max_repos and n >= args.max_repos:
            break
        batch = [t for t in next_targets(200, rescan=args.rescan) if t.get("slug") not in attempted]
        if not batch:
            break
        for t in batch:
            if args.max_repos and n >= args.max_repos:
                break
            attempted.add(t["slug"])
            n += 1
            if args.dry_run:
                print(f"[orch] ({n}) would analyze {t['slug']}")
                continue
            st = process_repo(t, args, logs, n, total)
            analyzed += st == "analyzed"
            skipped += st == "skipped"
            errored += st not in ("analyzed", "skipped")

    print(f"\n[orch] done. sessions={n} analyzed={analyzed} "
          f"error(retry later)={errored} skipped={skipped} "
          f"remaining≈{pending_count(rescan=args.rescan)}")


if __name__ == "__main__":
    main()
