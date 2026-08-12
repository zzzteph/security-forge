"""security-forge pipeline CLI — the deterministic glue around the agentic analysis.

The intelligence (finding real vulns, judging reachability) lives in the
`security-forge` skill and its subagents. This CLI just does the mechanical, testable
parts and gives the agent a clean interface to state:

    setup        create dirs, load .env
    update       clone/pull the target, report changed files + repo shape
    prep         update + repo shape in one shot (what a cycle starts with)
    shape        print repo shape only
    status       print finding counts
    get          list findings as JSON (filter by --status/--min-sev/--unreported)
    show         print one finding by id
    add-finding  record an agent-discovered finding (from --json or stdin)
    set-status   move a finding through its lifecycle / mark reported
    notify       emit a notification locally (stdout + per-target log)
    nuke         tear down the docker verification sandbox
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import repo  # noqa: E402
import store  # noqa: E402
from common import (ROOT, TARGET_DIR, configure_stdio, ensure_dirs, load_config,  # noqa: E402
                    load_env, eprint, fingerprint, now_iso)

configure_stdio()


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_setup(args) -> None:
    ensure_dirs()
    load_env()
    cfg = load_config()
    _print({"root": str(ROOT), "target_configured": bool((cfg.get("target") or {}).get("repo"))})


def cmd_update(args) -> None:
    ensure_dirs()
    cfg = load_config()
    result = repo.clone_or_update(cfg)
    result["shape"] = repo.detect_shape()
    _print(result)


def cmd_prep(args) -> None:
    """One call the skill runs at the top of a cycle: update repo + repo shape."""
    ensure_dirs()
    cfg = load_config()
    upd = repo.clone_or_update(cfg)
    commit = upd.get("commit")
    shape = repo.detect_shape()
    repo.write_last_commit(commit)
    _print({
        "when": now_iso(),
        "repo": upd.get("repo"),
        "commit": commit,
        "prev_commit": upd.get("prev_commit"),
        "is_first_scan": upd.get("is_first_scan"),
        "changed_files": upd.get("changed_files"),
        "changed_count": upd.get("changed_count"),
        "shape": shape,
        "counts": store.counts(),
    })


def cmd_shape(args) -> None:
    _print(repo.detect_shape())


def cmd_status(args) -> None:
    _print(store.counts())


def cmd_get(args) -> None:
    items = store.query(
        status=args.status,
        min_sev=args.min_sev,
        reported=(False if args.unreported else None),
        limit=args.limit,
    )
    if args.brief:
        items = [{"id": f["id"], "severity": f["severity"], "status": f["status"],
                  "reported": f.get("reported"), "fix_reported": f.get("fix_reported"),
                  "title": f["title"], "file": f.get("file"), "line": f.get("line")}
                 for f in items]
    _print(items)


def cmd_show(args) -> None:
    rec = store.get(args.id)
    if not rec:
        raise SystemExit(f"unknown finding id: {args.id}")
    _print(rec)


def cmd_add_finding(args) -> None:
    """Record an agent-discovered finding. JSON via --json or stdin.

    Required: title, severity. Optional: file, line, description, cwe, poc,
    rule, category. An id is derived if not supplied.
    """
    ensure_dirs()
    raw = args.json if args.json else (sys.stdin.read() if not sys.stdin.isatty() else "")
    if not raw.strip():
        raise SystemExit("provide finding JSON via --json '{...}' or stdin")
    data = json.loads(raw)
    if not data.get("title") or not data.get("severity"):
        raise SystemExit("finding requires at least 'title' and 'severity'")
    data.setdefault("tool", "claude")
    data.setdefault("source", "agent")
    data["severity"] = str(data["severity"]).upper()
    if not data.get("id"):
        data["id"] = fingerprint("agent", data.get("rule", data["title"]),
                                 data.get("file", ""), data.get("line", ""))
    rec = store.add_one(data, repo.current_commit())
    _print({"stored": rec["id"], "status": rec.get("status"), "record": rec})


def cmd_set_status(args) -> None:
    rec = store.set_status(args.id, args.status, note=args.note,
                           evidence=args.evidence, reported=args.reported,
                           fix_reported=args.fix_reported)
    _print({"id": rec["id"], "status": rec.get("status"),
            "reported": rec.get("reported"), "fix_reported": rec.get("fix_reported")})


def cmd_paths(args) -> None:
    """Show the resolved per-target paths (what SECFORGE_TARGET_REPO keys to)."""
    import os
    from common import (KNOWLEDGE_DIR, STATE_DIR, TARGET_DIR,  # noqa: E402
                        target_repo, target_slug)
    cfg = load_config()
    repo_url = target_repo(cfg)
    _print({
        "target_repo": repo_url,
        "slug": target_slug(repo_url),
        "env_SECFORGE_TARGET_REPO": os.environ.get("SECFORGE_TARGET_REPO", ""),
        "target_dir": str(TARGET_DIR),
        "state_dir": str(STATE_DIR),
        "knowledge_dir": str(KNOWLEDGE_DIR),
    })


def cmd_notify(args) -> None:
    """Emit a notification locally: print it and append to a per-target log.

    security-forge is notify-only and fully local — 'notifications' are progress lines,
    findings, and the cycle summary written to stdout (so the console / VS Code /
    CI logs show them) and appended to <knowledge_dir>/notifications.log for a
    durable record. No external service is contacted.
    """
    from common import KNOWLEDGE_DIR  # noqa: E402
    if args.file:
        p = Path(args.file)
        if not p.exists():
            eprint(f"[notify] report file not found: {p}")
        text = f"[report] {args.caption or p.name}: {p}"
    else:
        text = args.text or (sys.stdin.read() if not sys.stdin.isatty() else "")
        if not text.strip():
            raise SystemExit("nothing to emit")
    tag = "progress" if args.silent else "notice"
    line = f"[{now_iso()}] ({tag}) {text}"
    print(line)
    try:
        KNOWLEDGE_DIR.mkdir(parents=True, exist_ok=True)
        with (KNOWLEDGE_DIR / "notifications.log").open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError as e:  # a logging hiccup must never break a notify-only cycle
        eprint(f"[notify] could not append to log: {e}")
    _print({"emitted": True, "silent": bool(args.silent)})


def cmd_nuke(args) -> None:
    import verify
    _print(verify.nuke())


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="pipeline", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup").set_defaults(fn=cmd_setup)
    sub.add_parser("update").set_defaults(fn=cmd_update)
    sub.add_parser("prep").set_defaults(fn=cmd_prep)
    sub.add_parser("shape").set_defaults(fn=cmd_shape)
    sub.add_parser("status").set_defaults(fn=cmd_status)

    p = sub.add_parser("get")
    p.add_argument("--status"); p.add_argument("--min-sev")
    p.add_argument("--unreported", action="store_true"); p.add_argument("--limit", type=int)
    p.add_argument("--brief", action="store_true"); p.set_defaults(fn=cmd_get)

    p = sub.add_parser("show"); p.add_argument("id"); p.set_defaults(fn=cmd_show)

    p = sub.add_parser("add-finding"); p.add_argument("--json"); p.set_defaults(fn=cmd_add_finding)

    p = sub.add_parser("set-status")
    p.add_argument("id"); p.add_argument("status", nargs="?", default="")
    p.add_argument("--note"); p.add_argument("--evidence")
    p.add_argument("--reported", dest="reported", action="store_true", default=None)
    p.add_argument("--fix-reported", dest="fix_reported", action="store_true", default=None)
    p.set_defaults(fn=cmd_set_status)

    sub.add_parser("paths").set_defaults(fn=cmd_paths)

    p = sub.add_parser("notify")
    p.add_argument("text", nargs="?"); p.add_argument("--file"); p.add_argument("--caption")
    p.add_argument("--silent", action="store_true", help="mark as a progress ping rather than a finding/summary")
    p.set_defaults(fn=cmd_notify)

    sub.add_parser("nuke").set_defaults(fn=cmd_nuke)
    return ap


def main() -> None:
    ap = build_parser()
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
