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
    set-status   move a finding through its lifecycle / mark reported / link advisory+PoC
    verify-poc   run a finished PoC bundle end-to-end; mark `verified` ONLY if it
                 actually reproduces (exit 0 + success marker) — the advisory gate
    gc-advisories delete advisories + PoC bundles NOT backed by a reproduced finding
    export-reports collect findings into ONE flat reports/ folder (date_project_issue) + INDEX
    notify       emit a notification locally (stdout + per-target log)
    nuke         tear down the docker verification sandbox
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import os  # noqa: E402
import re  # noqa: E402
import repo  # noqa: E402
import store  # noqa: E402
from common import (ROOT, TARGET_DIR, DATA_ROOT, KNOWLEDGE_ROOT, KNOWLEDGE_DIR,  # noqa: E402
                    configure_stdio, ensure_dirs, load_config, load_env, eprint,
                    fingerprint, now_iso, sev_rank, target_slug)

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
                  "poc_verified": bool(f.get("poc_verified")),
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
                           fix_reported=args.fix_reported,
                           advisory_path=args.advisory_path, poc_dir=args.poc_dir)
    _print({"id": rec["id"], "status": rec.get("status"),
            "reported": rec.get("reported"), "fix_reported": rec.get("fix_reported"),
            "poc_verified": bool(rec.get("poc_verified")),
            "advisory_path": rec.get("advisory_path"), "poc_dir": rec.get("poc_dir")})


def cmd_verify_poc(args) -> None:
    """THE advisory gate: run a finished PoC bundle end-to-end and mark the finding
    `verified` ONLY if it actually reproduces (exit 0 + success marker). A failure
    clears `poc_verified` so `gc-advisories` will strip any advisory written on it.
    Exits non-zero when the bundle does not reproduce, so callers/CI can see it."""
    ensure_dirs()
    rec = store.get(args.id)
    if not rec:
        raise SystemExit(f"unknown finding id: {args.id}")
    poc_dir = args.dir or rec.get("poc_dir")
    if not poc_dir:
        raise SystemExit("no PoC bundle dir: pass --dir <bundle> (or record it on the "
                         "finding first with set-status --poc-dir)")
    import verify  # noqa: E402
    res = verify.verify_poc(poc_dir, project=args.project, script=args.script,
                            success_marker=args.success_marker, fail_marker=args.fail_marker,
                            up_timeout=args.up_timeout, run_timeout=args.run_timeout,
                            keep=args.keep)
    passed = bool(res.get("passed"))
    tail = (res.get("stdout_tail") or res.get("log_tail") or res.get("error") or "")
    ev = (f"PoC bundle {poc_dir}: passed={passed} exit={res.get('exit_code')} "
          f"phase={res.get('phase')} (marker '{res.get('success_marker', args.success_marker)}')\n"
          f"{tail[-1800:]}")
    if passed:
        store.set_status(args.id, "verified", evidence=ev, poc_verified=True,
                         poc_evidence=ev, poc_dir=str(poc_dir))
    else:
        # Do NOT flip to verified. Clear poc_verified and log the failure so the
        # advisory GC removes any advisory that was drafted on a false positive.
        store.set_status(args.id, "", poc_verified=False, poc_evidence=ev,
                         note=(f"PoC bundle did NOT reproduce (exit={res.get('exit_code')}, "
                               f"phase={res.get('phase')}) — not verified, advisory not warranted"))
    _print({"id": args.id, "passed": passed, **res})
    if not passed:
        raise SystemExit(3)


def cmd_gc_advisories(args) -> None:
    """Enforce 'advisory ⇔ reproduced': delete every advisory file and PoC bundle
    that is NOT backed by a `poc_verified` finding (i.e. one whose runnable bundle
    actually reproduced via verify-poc). Dry-run by default; --apply removes.

    Keep-set = the advisory_path / poc_dir recorded on poc_verified findings, so
    an advisory survives ONLY when its finding both reproduced AND linked the file.
    Anything else — advisories on dismissed/failed findings, orphans with no finding
    — is swept."""
    from common import KNOWLEDGE_DIR  # noqa: E402
    import shutil
    findings = store.query()
    keep_adv, keep_poc = set(), set()
    for f in findings:
        if not f.get("poc_verified"):
            continue
        if f.get("advisory_path"):
            keep_adv.add(str(Path(f["advisory_path"]).expanduser().resolve()))
        if f.get("poc_dir"):
            keep_poc.add(str(Path(f["poc_dir"]).expanduser().resolve()))
    removed_adv, kept_adv, removed_poc, kept_poc = [], [], [], []
    adv_dir = KNOWLEDGE_DIR / "advisories"
    if adv_dir.is_dir():
        for p in sorted(adv_dir.glob("*.md")):
            if p.name.lower() == "readme.md":
                continue
            (kept_adv if str(p.resolve()) in keep_adv else removed_adv).append(str(p))
    poc_root = KNOWLEDGE_DIR / "poc"
    if poc_root.is_dir():
        for d in sorted(x for x in poc_root.iterdir() if x.is_dir()):
            (kept_poc if str(d.resolve()) in keep_poc else removed_poc).append(str(d))
    if args.apply:
        for p in removed_adv:
            try:
                Path(p).unlink()
            except OSError as e:
                eprint(f"[gc] could not remove {p}: {e}")
        for d in removed_poc:
            shutil.rmtree(d, ignore_errors=True)
    _print({"applied": bool(args.apply),
            "poc_verified_findings": sum(1 for f in findings if f.get("poc_verified")),
            "advisories_removed": removed_adv, "advisories_kept": kept_adv,
            "poc_removed": removed_poc, "poc_kept": kept_poc})


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


# --- Central report export --------------------------------------------------
# Every finding across every project lands as one file in ONE flat folder, so the
# vulnerabilities are browsable regardless of which repo they came from:
#   <reports_dir>/<YYYYMMDD>_<project>_<SEV>_<issue>.md   +   INDEX.md

def reports_dir(cli: str | None = None) -> Path:
    """Central reports folder. Precedence: --reports-dir > SECFORGE_REPORTS_DIR >
    config.yaml report.reports_dir > DATA_ROOT/reports."""
    p = (cli or os.environ.get("SECFORGE_REPORTS_DIR") or "").strip()
    if not p:
        try:
            p = ((load_config().get("report") or {}).get("reports_dir") or "").strip()
        except SystemExit:
            p = ""
    return Path(p).expanduser().resolve() if p else (DATA_ROOT / "reports")


def _rslug(s: str, n: int = 48) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", (s or "").strip().lower()).strip("-")
    return (s[:n].rstrip("-") or "issue")


def _project_of(slug: str) -> str:
    parts = [p for p in (slug or "").split("/") if p]
    name = "-".join(parts[1:]) if len(parts) >= 3 else (parts[-1] if parts else slug)
    return re.sub(r"[^A-Za-z0-9._-]", "-", name or "project") or "project"


def _report_date(f: dict) -> str:
    d = (f.get("first_seen") or f.get("last_seen") or f.get("updated") or now_iso())
    return re.sub(r"[^0-9]", "", str(d)[:10]) or "00000000"


def _report_name(f: dict, slug: str) -> str:
    sev = (f.get("severity") or "NA").upper()
    return (f"{_report_date(f)}_{_project_of(slug)}_{sev}_"
            f"{_rslug(f.get('title') or f.get('category') or f.get('id'))}.txt")


def _render_report(f: dict, slug: str) -> str:
    """A plain, compact text report — no markdown headers/bold/fences/emoji, single
    blank lines. Meant to be read and grepped, not rendered."""
    lines: list[str] = []
    lines.append(f"[{(f.get('severity') or 'NA').upper()}] {f.get('title') or f.get('id')}")
    lines.append("")

    def kv(label: str, val) -> None:
        if val:
            lines.append(f"{label + ':':<13} {val}")

    loc = f.get("file") or ""
    if loc and f.get("line"):
        loc += f":{f.get('line')}"
    cwe = f.get("cwe")
    if isinstance(cwe, list):
        cwe = ", ".join(cwe)
    verified = ("yes" if f.get("poc_verified")
                else "runtime-confirmed" if f.get("status") == "verified" else "no")
    kv("Project", slug)
    kv("Status", f.get("status"))
    kv("PoC verified", verified)
    kv("Where", loc)
    kv("Category", f.get("category"))
    kv("CWE", cwe)
    kv("Commit", f.get("commit_sha") or f.get("last_commit"))
    kv("Entry point", f.get("entrypoint"))

    def section(title: str, body) -> None:
        body = ("" if body is None else str(body)).rstrip()
        if body:
            lines.append("")
            lines.append(title)
            lines.extend(body.splitlines())

    section("Reachability:", f.get("reachability"))
    section("Severity rationale:", f.get("severity_rationale"))
    section("PoC:", f.get("poc"))
    section("Evidence:", str(f.get("evidence"))[:6000] if f.get("evidence") else None)

    if f.get("advisory_path"):
        lines.append("")
        kv("Advisory", f["advisory_path"])
    if f.get("poc_dir"):
        kv("PoC bundle", f"{f['poc_dir']}  (docker compose up -d && python poc.py)")

    lines.append("")
    lines.append(f"id {f.get('id')} · exported {now_iso()[:10]}")
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).rstrip() + "\n"
    return text


def _collect_findings(all_projects: bool) -> list[tuple[dict, str]]:
    """(finding, slug) pairs to export. Default: the current target's store; --all:
    every project's store under knowledge/."""
    out: list[tuple[dict, str]] = []
    if all_projects:
        import json as _json
        for fp in sorted(KNOWLEDGE_ROOT.glob("*/*/*/findings.json")):
            slug = fp.parent.relative_to(KNOWLEDGE_ROOT).as_posix()
            try:
                db = _json.loads(fp.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            for f in (db.values() if isinstance(db, dict) else []):
                if f.get("id"):
                    out.append((f, slug))
    else:
        slug = target_slug(os.environ.get("SECFORGE_TARGET")
                           or os.environ.get("SECFORGE_TARGET_REPO") or "")
        for f in store.query():
            out.append((f, slug or (f.get("slug") or "target")))
    return out


def _write_index(rdir: Path, rows: list[tuple[str, dict, str]]) -> None:
    """Plain, aligned, greppable index — no markdown table. Highest severity first."""
    rows = sorted(rows, key=lambda r: (-sev_rank(r[1].get("severity")), r[0]))
    out = [f"security-forge findings — {len(rows)} across all projects "
           f"— updated {now_iso()[:16].replace('T', ' ')}", ""]
    out.append(f"{'SEVERITY':<9} {'V':<1} {'PROJECT':<22} {'STATUS':<10} "
               f"{'WHERE':<26} FILE")
    for name, f, slug in rows:
        loc = (f.get("file") or "")
        if loc and f.get("line"):
            loc += f":{f['line']}"
        out.append(f"{(f.get('severity') or 'NA').upper():<9} "
                   f"{('Y' if f.get('poc_verified') else '-'):<1} "
                   f"{_project_of(slug)[:22]:<22} {(f.get('status') or ''):<10} "
                   f"{loc[:26]:<26} {name}")
    (rdir / "INDEX.txt").write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    # drop a stale markdown index from before the plain-text switch
    try:
        (rdir / "INDEX.md").unlink()
    except OSError:
        pass


def cmd_export_reports(args) -> None:
    """Export findings to the central, project-flat reports folder + a global INDEX.
    Non-dismissed findings at/above --min-sev. Idempotent: filenames are stable, and
    files we generated for findings that no longer qualify are pruned (tracked in a
    manifest, so your own files in the folder are never touched)."""
    import json as _json
    rdir = reports_dir(args.reports_dir)
    rdir.mkdir(parents=True, exist_ok=True)
    floor = sev_rank(args.min_sev or "MEDIUM")
    pairs = [(f, s) for (f, s) in _collect_findings(args.all)
             if f.get("status") != "dismissed" and sev_rank(f.get("severity")) >= floor]
    written, rows = [], []
    for f, slug in pairs:
        name = _report_name(f, slug)
        (rdir / name).write_text(_render_report(f, slug), encoding="utf-8")
        written.append(name)
        rows.append((name, f, slug))
    # prune report files we generated before but that no longer qualify
    manifest = rdir / ".secforge_reports.json"
    prev = []
    if manifest.exists():
        try:
            prev = _json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = []
    for old in set(prev) - set(written):
        try:
            (rdir / old).unlink()
        except OSError:
            pass
    manifest.write_text(_json.dumps(sorted(set(written))), encoding="utf-8")
    _write_index(rdir, rows)
    _print({"reports_dir": str(rdir), "written": len(written),
            "pruned": len(set(prev) - set(written)), "index": str(rdir / "INDEX.txt")})


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
    p.add_argument("--advisory-path", help="link the advisory file written for this finding "
                   "(required for it to survive gc-advisories)")
    p.add_argument("--poc-dir", help="link this finding's runnable PoC bundle folder")
    p.set_defaults(fn=cmd_set_status)
    # NOTE: poc_verified is deliberately NOT settable here — only `verify-poc` may
    # set it, by actually running the bundle. That is what keeps it trustworthy.

    p = sub.add_parser("verify-poc")
    p.add_argument("id"); p.add_argument("--dir", help="the PoC bundle folder (else the "
                   "finding's recorded poc_dir)"); p.add_argument("--project")
    p.add_argument("--script", default="poc.py")
    p.add_argument("--success-marker", default="EXPLOITED")
    p.add_argument("--fail-marker", default="NOT VULNERABLE")
    p.add_argument("--up-timeout", type=int, default=1800)
    p.add_argument("--run-timeout", type=int, default=900)
    p.add_argument("--keep", action="store_true", help="don't tear the bundle down after")
    p.set_defaults(fn=cmd_verify_poc)

    p = sub.add_parser("gc-advisories")
    p.add_argument("--apply", action="store_true", help="actually delete (default: dry-run)")
    p.set_defaults(fn=cmd_gc_advisories)

    p = sub.add_parser("export-reports")
    p.add_argument("--all", action="store_true", help="export EVERY project's findings "
                   "(default: just the current target)")
    p.add_argument("--min-sev", default="MEDIUM")
    p.add_argument("--reports-dir", help="central folder (default: SECFORGE_REPORTS_DIR "
                   "or <data>/reports)")
    p.set_defaults(fn=cmd_export_reports)

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
