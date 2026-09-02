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
    """Folder for the per-repo EXECUTIVE report (summary + auth map + findings
    table). Precedence: --reports-dir > SECFORGE_REPORTS_DIR > config.yaml
    report.reports_dir > DATA_ROOT/reports."""
    p = (cli or os.environ.get("SECFORGE_REPORTS_DIR") or "").strip()
    if not p:
        try:
            p = ((load_config().get("report") or {}).get("reports_dir") or "").strip()
        except SystemExit:
            p = ""
    return Path(p).expanduser().resolve() if p else (DATA_ROOT / "reports")


def findings_dir() -> Path:
    """Dedicated folder for individual finding advisories, one file per finding
    under <org>__<repo>/. SECFORGE_FINDINGS_DIR > config report.findings_dir >
    DATA_ROOT/findings."""
    p = (os.environ.get("SECFORGE_FINDINGS_DIR") or "").strip()
    if not p:
        try:
            p = ((load_config().get("report") or {}).get("findings_dir") or "").strip()
        except SystemExit:
            p = ""
    return Path(p).expanduser().resolve() if p else (DATA_ROOT / "findings")


def _repo_key(slug: str) -> str:
    """<org>__<repo> stem used for the report filename and findings subfolder."""
    return _report_filename(slug)[:-3]


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


def _org_repo(slug: str) -> tuple[str, str]:
    """(org, repo) from a host/org/repo slug."""
    parts = [p for p in (slug or "").split("/") if p]
    org = parts[1] if len(parts) >= 3 else (parts[0] if parts else "org")
    repo = parts[2] if len(parts) >= 3 else (parts[-1] if parts else "repo")
    return org, repo


def _report_filename(slug: str) -> str:
    """One executive report per repo: <org>__<repo>.md."""
    org, repo = _org_repo(slug)
    safe = lambda s: (re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "x")
    return f"{safe(org)}__{safe(repo)}.md"


def _knowledge_doc(slug: str, name: str, cap: int = 12000) -> str:
    """Read a durable knowledge doc (AUTH.md / ROLES.md / ...) for this repo, or ''."""
    try:
        p = KNOWLEDGE_ROOT / slug / name
        if not p.is_file():
            return ""
        t = p.read_text(encoding="utf-8", errors="replace").strip()
        return t if len(t) <= cap else t[:cap] + "\n\n… [truncated]"
    except Exception:  # noqa: BLE001
        return ""


def _advisory_body(f: dict) -> list[str]:
    """Meta line + explained sections for one finding (no heading). Shared by the
    standalone advisory file and any inline rendering."""
    sev = (f.get("severity") or "NA").upper()
    cwe = f.get("cwe")
    cwe = ", ".join(cwe) if isinstance(cwe, list) else (cwe or "")
    where = f.get("file") or ""
    if where and f.get("line"):
        where += f":{f.get('line')}"
    verified = ("yes" if f.get("poc_verified")
                else "runtime-confirmed" if f.get("status") == "verified" else "no")
    conf = f.get("verdict") or f.get("confidence") or ""
    meta = []
    if f.get("entrypoint"):
        meta.append(f"**Endpoint:** `{f['entrypoint']}`")
    if f.get("category"):
        meta.append(f"**Type:** {f['category']}")
    if where:
        meta.append(f"**Location:** `{where}`")
    if cwe:
        meta.append(f"**CWE:** {cwe}")
    meta.append(f"**Severity:** {sev} · **Status:** {f.get('status') or 'new'} · "
                f"PoC verified: {verified}" + (f" · Confidence: {conf}" if conf else ""))
    L = [" · ".join(meta)]

    def sect(h: str, body) -> None:
        body = ("" if body is None else str(body)).strip()
        if body:
            L.extend(["", f"**{h}**", "", body])

    sect("Summary", f.get("description") or f.get("summary"))
    sect("Impact", f.get("impact"))
    sect("Why it happens (root cause)", f.get("root_cause") or f.get("why"))
    sect("Attacker path / reachability", f.get("reachability") or f.get("trace"))
    sect("Severity rationale", f.get("severity_rationale"))
    sect("Remediation", f.get("remediation") or f.get("fix"))
    sect("Proof of concept", f.get("poc"))
    if f.get("evidence"):
        sect("Evidence", str(f.get("evidence"))[:4000])
    tail = []
    if f.get("advisory_path"):
        tail.append(f"advisory: `{f['advisory_path']}`")
    if f.get("poc_dir"):
        tail.append(f"PoC bundle: `{f['poc_dir']}`")
    if tail:
        L.extend(["", "_" + " · ".join(tail) + "_"])
    return L


def _advisory_filename(f: dict) -> str:
    """<sev>-<title-slug>.md for the dedicated per-finding advisory file."""
    sev = (f.get("severity") or "NA").upper()
    return f"{sev}-{_rslug(f.get('title') or f.get('category') or f.get('id'))}.md"


def _advisory_doc(f: dict, slug: str) -> str:
    """Standalone advisory file for one finding (its own dedicated document)."""
    org, repo = _org_repo(slug)
    sev = (f.get("severity") or "NA").upper()
    title = f.get("title") or f.get("id") or "finding"
    commit = f.get("commit_sha") or f.get("last_commit") or ""
    ctx = (f"_Repo: {org}/{repo}" + (f" · commit `{commit[:12]}`" if commit else "")
           + (f" · id `{f.get('id')}`" if f.get("id") else "") + "_")
    return f"# [{sev}] {title}\n\n{ctx}\n\n" + "\n".join(_advisory_body(f)) + "\n"


def _anchor(title: str) -> str:
    """GitHub-flavoured heading anchor for a section/finding title."""
    a = re.sub(r"[^\w\s-]", "", (title or "").strip().lower())
    return re.sub(r"\s+", "-", a).strip("-") or "section"


def _render_repo_report(slug: str, findings: list[dict], adv_links: dict | None = None) -> str:
    """The CISO-shareable executive report for ONE repo: table of contents,
    summary, what was done, the authorization map, and a findings table that links
    out to each finding's dedicated advisory file under findings/<org>__<repo>/."""
    adv_links = adv_links or {}
    org, repo = _org_repo(slug)
    fs = sorted(findings, key=lambda f: (-sev_rank(f.get("severity")), f.get("title") or ""))

    def n(s):
        return sum(1 for f in fs if (f.get("severity") or "").upper() == s)
    c, h, m = n("CRITICAL"), n("HIGH"), n("MEDIUM")
    commit = ""
    for f in fs:
        commit = f.get("commit_sha") or f.get("last_commit") or commit
    verdict = "VULNERABLE" if (c or h or m) else "no MEDIUM-or-higher findings recorded"

    # Build the body first, recording each top-level (##) section for the TOC.
    body: list[str] = []
    toc: list[str] = []

    def section(title: str):
        toc.append(title)
        body.extend([f"## {title}", ""])

    section("Executive summary")
    exec_doc = _knowledge_doc(slug, "EXECUTIVE_SUMMARY.md")
    if exec_doc:
        body.append(exec_doc)
    else:
        top = "; ".join(f"{(f.get('severity') or '').upper()} — {f.get('title')}" for f in fs[:5])
        body.append(f"security-forge reviewed **{org}/{repo}** for broken access control and "
                    f"related application-layer risks. This cycle recorded **{c} Critical, {h} "
                    f"High and {m} Medium** issues."
                    + (f" Highest-impact: {top}." if top else
                       " No MEDIUM-or-higher access-control issues were recorded."))
    body.append("")

    section("What was done")
    proj = _knowledge_doc(slug, "PROJECT.md", cap=4000)
    if proj:
        body.extend([proj, ""])
    body.append("**Method.** Static review driven by the durable project model: every entry point "
                "was enumerated and mapped to its authentication and authorization; each "
                "data-bearing or state-changing route was checked for missing authentication, "
                "broken object-level authorization (BOLA/IDOR), broken function-level authorization "
                "(BFLA), tenant/ownership gaps, and enumerable identifiers. The findings below are "
                "the access-control gaps that cleared the bar. Dynamic (DAST) sandbox verification "
                "was not run for this report unless a finding is marked *PoC verified*.")
    body.append("")

    section("Authorization map")
    auth = _knowledge_doc(slug, "AUTH.md")
    roles = _knowledge_doc(slug, "ROLES.md")
    eps = _knowledge_doc(slug, "ENTRYPOINTS.md")
    if auth:
        body.extend(["### Authentication & authorization", "", auth, ""])
    if roles:
        body.extend(["### Roles / principals", "", roles, ""])
    if eps:
        body.extend(["### Entry points", "", eps, ""])
    if not (auth or roles or eps):
        body.extend(["_No durable auth model (AUTH/ROLES/ENTRYPOINTS) was captured for this repo._", ""])

    tb = _knowledge_doc(slug, "TRUST_BOUNDARIES.md")
    if tb:
        section("Trust boundaries")
        body.extend([tb, ""])
    di = _knowledge_doc(slug, "DISCLOSURE_INDEX.md")
    if di:
        section("Disclosure surface")
        body.extend([di, ""])

    section("Findings")
    if not fs:
        body.append("_No MEDIUM-or-higher findings were recorded for this repo in this cycle._")
    else:
        body.append(f"Full advisories are in `findings/{_repo_key(slug)}/` (one file per "
                    f"finding, linked below).")
        body.extend(["", "| # | Severity | Finding | Type | Location | Status |",
                     "|--:|---|---|---|---|---|"])
        for i, f in enumerate(fs, 1):
            sev = (f.get("severity") or "NA").upper()
            title = (f.get("title") or f.get("id") or "finding").replace("|", "\\|")
            loc = f.get("entrypoint") or f.get("file") or ""
            if not f.get("entrypoint") and f.get("file") and f.get("line"):
                loc += f":{f['line']}"
            loc = str(loc).replace("|", "\\|")
            link = adv_links.get(f.get("id") or "")
            finding_cell = f"[{title}]({link})" if link else title
            body.append(f"| {i} | {sev} | {finding_cell} | {f.get('category') or ''} | "
                        f"`{loc}` | {f.get('status') or 'new'} |")

    # Header + TOC, then the body.
    L = [f"# {org}/{repo} — Security Review", ""]
    L.append(f"**Result:** {verdict} — {c} Critical · {h} High · {m} Medium"
             + (f" · commit `{commit[:12]}`" if commit else ""))
    L.append(f"_Generated {now_iso()[:16].replace('T', ' ')} by security-forge "
             f"(static access-control review)._")
    L.append("")
    L.append("## Contents")
    L.append("")
    for t in toc:
        L.append(f"- [{t}](#{_anchor(t)})")
    L.append("")
    L.extend(body)
    return re.sub(r"\n{3,}", "\n\n", "\n".join(L)).rstrip() + "\n"


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


def _analyzed_slugs() -> set[str]:
    """Every repo that has a durable knowledge/ model or findings store — so every
    scanned repo gets an executive report, even ones with zero findings."""
    slugs: set[str] = set()
    try:
        for p in KNOWLEDGE_ROOT.glob("*/*/*"):
            if p.is_dir() and ((p / "model.json").exists() or (p / "findings.json").exists()
                               or (p / "AUTH.md").exists()):
                slugs.add(p.relative_to(KNOWLEDGE_ROOT).as_posix())
    except Exception:  # noqa: BLE001
        pass
    return slugs


def _write_index(rdir: Path, rows: list[tuple]) -> None:
    """Markdown index: one row per repo, most-severe first, linking each report."""
    rows = sorted(rows, key=lambda r: (-(r[2] * 100 + r[3] * 10 + r[4]), r[0]))
    out = ["# security-forge — findings index", "",
           f"_{len(rows)} repositories · updated {now_iso()[:16].replace('T', ' ')}_", "",
           "| Repository | Critical | High | Medium | Report |",
           "|---|--:|--:|--:|---|"]
    tc = th = tm = 0
    for slug, name, c, h, m in rows:
        org, repo = _org_repo(slug)
        out.append(f"| {org}/{repo} | {c} | {h} | {m} | [{name}]({name}) |")
        tc += c; th += h; tm += m
    out.append(f"| **Total** | **{tc}** | **{th}** | **{tm}** | |")
    (rdir / "INDEX.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    for stale in ("INDEX.txt",):   # drop the old plain-text index
        try:
            (rdir / stale).unlink()
        except OSError:
            pass


def cmd_export_reports(args) -> None:
    """Write, per scanned repo, an EXECUTIVE report to reports/<org>__<repo>.md
    (summary + what-was-done + authorization map + a findings table) and a dedicated
    ADVISORY file per finding to findings/<org>__<repo>/<sev>-<slug>.md, plus a
    markdown INDEX. Pruning is scoped per repo: a single-repo export only touches
    its own report + advisory folder, never other repos'. In --all mode, reports
    for repos that dropped out entirely are also pruned (manifest-tracked)."""
    import json as _json
    import shutil
    rdir = reports_dir(args.reports_dir)
    fdir = findings_dir()
    rdir.mkdir(parents=True, exist_ok=True)
    fdir.mkdir(parents=True, exist_ok=True)
    floor = sev_rank(args.min_sev or "MEDIUM")

    # Load EVERY repo's findings (cheap: small JSON files) so the INDEX is always
    # complete regardless of which repo(s) we regenerate this call.
    all_by_slug: dict[str, list[dict]] = {}
    for f, slug in _collect_findings(True):
        if f.get("status") == "dismissed" or sev_rank(f.get("severity")) < floor:
            continue
        all_by_slug.setdefault(slug, []).append(f)

    # Scope of reports to (re)generate this call: current target by default, all with --all.
    if args.all:
        scope = set(all_by_slug) | _analyzed_slugs()
    else:
        s = target_slug(os.environ.get("SECFORGE_TARGET")
                        or os.environ.get("SECFORGE_TARGET_REPO") or "")
        scope = {s} if s else set()

    written_reports, total_adv = [], 0
    for slug in sorted(scope):
        fs = sorted(all_by_slug.get(slug, []),
                    key=lambda f: (-sev_rank(f.get("severity")), f.get("title") or ""))
        key = _repo_key(slug)
        # 1) dedicated advisory file per finding, in findings/<org>__<repo>/
        sub = fdir / key
        adv_links: dict[str, str] = {}
        written_adv: set[str] = set()
        if fs:
            sub.mkdir(parents=True, exist_ok=True)
            seen: dict[str, int] = {}
            for f in fs:
                fn = _advisory_filename(f)
                if fn in seen:      # de-dup identical filenames within a repo
                    seen[fn] += 1
                    fn = fn[:-3] + f"-{seen[fn]}.md"
                else:
                    seen[fn] = 0
                (sub / fn).write_text(_advisory_doc(f, slug), encoding="utf-8")
                written_adv.add(fn)
                adv_links[f.get("id") or fn] = f"../findings/{key}/{fn}"
            total_adv += len(written_adv)
            # prune stale advisories for THIS repo only
            for old in sub.glob("*.md"):
                if old.name not in written_adv:
                    try:
                        old.unlink()
                    except OSError:
                        pass
        elif sub.exists():          # repo now has no findings -> drop its folder
            shutil.rmtree(sub, ignore_errors=True)

        # 2) executive report per repo, linking out to the advisory files
        name = _report_filename(slug)
        (rdir / name).write_text(_render_repo_report(slug, fs, adv_links), encoding="utf-8")
        written_reports.append(name)

    # In --all mode, prune reports + advisory folders for repos that vanished.
    manifest = rdir / ".secforge_reports.json"
    if args.all:
        prev = []
        if manifest.exists():
            try:
                prev = _json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prev = []
        for old in set(prev) - set(written_reports):
            try:
                (rdir / old).unlink()
            except OSError:
                pass
            stale_sub = fdir / old[:-3]
            if stale_sub.exists():
                shutil.rmtree(stale_sub, ignore_errors=True)
        manifest.write_text(_json.dumps(sorted(set(written_reports))), encoding="utf-8")
    else:
        # single-repo: keep the manifest a superset so --all later still knows all repos
        prev = []
        if manifest.exists():
            try:
                prev = _json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prev = []
        manifest.write_text(_json.dumps(sorted(set(prev) | set(written_reports))), encoding="utf-8")

    # INDEX always covers EVERY repo that has a report on disk (not just the ones
    # regenerated this call), with fresh counts from all_by_slug.
    index_rows = []
    for slug in sorted(set(all_by_slug) | _analyzed_slugs()):
        name = _report_filename(slug)
        if not (rdir / name).exists():
            continue
        fs = all_by_slug.get(slug, [])
        sev = lambda s: sum(1 for f in fs if (f.get("severity") or "").upper() == s)
        index_rows.append((slug, name, sev("CRITICAL"), sev("HIGH"), sev("MEDIUM")))
    _write_index(rdir, index_rows)
    _print({"reports_dir": str(rdir), "findings_dir": str(fdir),
            "regenerated": len(written_reports), "advisories_written": total_adv,
            "index_repos": len(index_rows), "index": str(rdir / "INDEX.md")})


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
    # Default: only the current target repo (cheap, and it never wipes other repos —
    # pruning is scoped per repo, and the INDEX is always rebuilt across all repos).
    # --all regenerates every analyzed repo's report + advisories.
    p.add_argument("--all", action="store_true",
                   help="regenerate reports for EVERY analyzed repo (default: current target only)")
    p.add_argument("--min-sev", default="MEDIUM")
    p.add_argument("--reports-dir", help="exec-report folder (default: SECFORGE_REPORTS_DIR "
                   "or <data>/reports; advisories go to <data>/findings)")
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
