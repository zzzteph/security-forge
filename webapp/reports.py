"""Advisory + executive report rendering, and PDF export.

Every finding is presented in the GHSA-style advisory format the pipeline already
uses. We render Markdown -> styled HTML, and (via WeasyPrint) HTML -> PDF for
download. An executive report aggregates a repo's (or all repos') current findings.
"""
from __future__ import annotations

import html
import json

import db

_CSS = """
@page { size: A4; margin: 20mm 18mm; }
* { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
body { color: #1a1a1a; font-size: 11pt; line-height: 1.45; }
h1 { font-size: 17pt; margin: 0 0 4pt; }
h2 { font-size: 12.5pt; border-bottom: 1px solid #ddd; padding-bottom: 2pt; margin: 16pt 0 6pt; }
code, pre { font-family: "SF Mono", "Consolas", monospace; font-size: 9.5pt; }
pre { background: #f5f5f7; padding: 8pt; border-radius: 4pt; white-space: pre-wrap;
      word-wrap: break-word; border: 1px solid #eee; }
.badge { display: inline-block; padding: 1pt 8pt; border-radius: 3pt; color: #fff;
         font-weight: 700; font-size: 10pt; }
.CRITICAL { background: #b4232c; } .HIGH { background: #d9822b; }
.MEDIUM { background: #b59a00; } .LOW { background: #6b7280; }
table { border-collapse: collapse; width: 100%; font-size: 10pt; margin: 6pt 0; }
th, td { border: 1px solid #ddd; padding: 4pt 6pt; text-align: left; }
th { background: #f0f0f2; }
.meta { color: #555; font-size: 9.5pt; margin-bottom: 10pt; }
.muted { color: #888; }
"""


def _sec(title: str, body) -> str:
    body = ("" if body is None else str(body)).strip()
    return f"## {title}\n\n{body}\n\n" if body else ""


def _deep_exploration(f: dict) -> str:
    """Surface the deep per-finding analysis the engine captured but that isn't a
    first-class column: its false-positive self-check and the timestamped analysis
    trail (re-scoping, source->sink reasoning). Parsed from `raw` so every finding
    shows the full depth it was analyzed with; '' when the engine recorded none."""
    try:
        extra = json.loads(f.get("raw") or "{}")
    except (ValueError, TypeError):
        return ""
    if not isinstance(extra, dict):
        return ""
    out = _sec("False-positive self-check", extra.get("fp_filter_checked"))
    notes = extra.get("notes")
    if isinstance(notes, list):
        lines = []
        for n in notes:
            if isinstance(n, dict) and (n.get("note") or "").strip():
                ts = str(n.get("ts") or "")[:19].replace("T", " ")
                lines.append(f"- {('`' + ts + '` — ') if ts else ''}{n['note'].strip()}")
            elif isinstance(n, str) and n.strip():
                lines.append(f"- {n.strip()}")
        if lines:
            out += "## Analysis trail\n\n" + "\n".join(lines) + "\n\n"
    return out


def advisory_markdown(f: dict) -> str:
    sev = (f.get("severity") or "NA").upper()
    loc = f.get("file") or ""
    if loc and f.get("line"):
        loc += f":{f['line']}"
    status = f.get("status") or "open"
    md = [f"# [{sev}] {f.get('title') or f.get('fid') or f.get('id')}\n\n"]
    meta = [f"**Project:** {f.get('slug')}", f"**Severity:** {sev}",
            f"**Status:** {status}"]
    if loc:
        meta.append(f"**Location:** `{loc}`")
    if f.get("cwe"):
        meta.append(f"**CWE:** {f['cwe']}")
    if f.get("category"):
        meta.append(f"**Category:** {f['category']}")
    if f.get("last_commit"):
        meta.append(f"**Commit:** {f['last_commit'][:12]}")
    md.append(" · ".join(meta) + "\n\n")
    if status == "mitigated" and f.get("mitigation_reason"):
        md.append(f"> **Mitigated.** {f['mitigation_reason']}\n\n")
    md.append(_sec("Summary", f.get("description")))
    md.append(_sec("Root cause", f.get("root_cause")))
    md.append(_sec("Reachability", f.get("reachability")))
    md.append(_sec("Impact", f.get("impact")))
    if f.get("poc"):
        md.append("## Proof of concept\n\n```\n" + str(f["poc"]).strip() + "\n```\n\n")
    md.append(_sec("Remediation", f.get("remediation")))
    md.append(_sec("Severity rationale", f.get("severity_rationale")))
    if f.get("entrypoint"):
        md.append(_sec("Affected entry points", f.get("entrypoint")))
    md.append(_deep_exploration(f))
    md.append(f"\n---\n*Finding `{f.get('fid') or f.get('id')}` · "
              f"first seen {f.get('first_seen')} · last seen {f.get('last_seen')}*\n")
    return "".join(md)


def _md_to_html(md: str) -> str:
    try:
        import markdown as _m
        return _m.markdown(md, extensions=["fenced_code", "tables"])
    except Exception:  # noqa: BLE001  (fallback: escaped <pre> so PDF still renders)
        return "<pre>" + html.escape(md) + "</pre>"


def _page(title: str, body_html: str) -> str:
    # badge coloring for severity words in headings
    body_html = body_html.replace("[CRITICAL]", '<span class="badge CRITICAL">CRITICAL</span>')\
        .replace("[HIGH]", '<span class="badge HIGH">HIGH</span>')\
        .replace("[MEDIUM]", '<span class="badge MEDIUM">MEDIUM</span>')\
        .replace("[LOW]", '<span class="badge LOW">LOW</span>')
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
            f"<style>{_CSS}</style></head><body>{body_html}</body></html>")


def advisory_html(f: dict) -> str:
    return _page(f.get("title") or "advisory", _md_to_html(advisory_markdown(f)))


def markdown_fragment(md: str) -> str:
    """Render markdown to an HTML fragment (no <html>/<head> wrapper) with severity
    words turned into pills — for in-app 'rendered' viewing of advisories and reports.
    The page styles it under `.md`."""
    body = _md_to_html(md or "")
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"):
        body = body.replace(f"[{s}]", f'<span class="badge {s}">{s}</span>')
    return body


def executive_markdown(repo_id: int | None = None) -> str:
    findings = db.list_findings(repo_id=repo_id)
    openf = [f for f in findings if f.get("status") == "open"]
    scope = "all monitored repositories"
    if repo_id:
        r = db.get_repo(repo_id)
        scope = r["slug"] if r else f"repo {repo_id}"
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    by = {s: [f for f in openf if (f.get("severity") or "").upper() == s] for s in order}
    md = [f"# Executive summary — {scope}\n\n",
          f"_{len(openf)} open finding(s); "
          f"{len([f for f in findings if f.get('status')=='mitigated'])} mitigated. "
          f"Generated {db._now()}._\n\n",
          "## Risk posture\n\n| Severity | Open |\n|---|---|\n"]
    for s in order:
        md.append(f"| {s} | {len(by[s])} |\n")
    md.append("\n## Findings\n\n")
    if not openf:
        md.append("_No open findings that meet the reporting bar._\n")
    for s in order:
        for f in by[s]:
            loc = (f.get("file") or "")
            if loc and f.get("line"):
                loc += f":{f['line']}"
            md.append(f"### [{s}] {f.get('title')}\n\n"
                      f"**{f.get('slug')}** · `{loc}`" + (f" · {f['cwe']}" if f.get('cwe') else "")
                      + "\n\n" + (f.get("description") or "") + "\n\n")
            if f.get("remediation"):
                md.append(f"*Fix:* {f['remediation']}\n\n")
    return "".join(md)


def executive_html(repo_id: int | None = None) -> str:
    return _page("Executive summary", _md_to_html(executive_markdown(repo_id)))


def to_pdf(html_str: str) -> bytes:
    """Render an HTML string to PDF bytes via WeasyPrint."""
    from weasyprint import HTML
    return HTML(string=html_str).write_pdf()


# ============================================================================
# JET-format executive report (navy/orange cover, severity pills, stat tiles,
# callout boxes, Trace & fix code blocks + PoCs). The narrative half is written
# by the AI; the technical appendix is rendered deterministically from findings
# so code and PoCs are always accurate. See reportgen.py for the job that builds
# the stored markdown artifact this renders.
# ============================================================================

import re as _re

_SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEV_HEX = {"CRITICAL": "#C1121F", "HIGH": "#E8590C", "MEDIUM": "#E0A100",
            "LOW": "#6B7280", "SAFE": "#2B8A3E"}

_JET_CSS = """
@page { size: A4; margin: 18mm 16mm 20mm 16mm;
  @bottom-left   { content: "JET · Smart Gateway Security Programme"; color:#6B7280; font: 8pt "Segoe UI",sans-serif; }
  @bottom-center { content: "CONFIDENTIAL"; color:#C1121F; font: 700 8pt "Segoe UI",sans-serif; }
  @bottom-right  { content: counter(page); color:#6B7280; font: 8pt "Segoe UI",sans-serif; } }
@page cover { margin: 0; @bottom-left{content:none} @bottom-center{content:none} @bottom-right{content:none} }
* { font-family: "Segoe UI", -apple-system, Roboto, Helvetica, Arial, sans-serif; box-sizing: border-box; }
body { color:#1A1D23; font-size:10.5pt; line-height:1.5; margin:0; }

/* ---- cover ---- */
.cover { page: cover; height: 297mm; width:100%; background:#14213D; color:#fff; position:relative; }
.cover .band { position:absolute; top:120mm; left:0; right:0; height:9px; background:#FB6A02; }
.cover .top { position:absolute; top:20mm; left:20mm; right:20mm; display:flex;
              justify-content:space-between; color:#c7d0e4; font-size:11pt; }
.cover .top b { color:#fff; } .cover .top .accent { color:#FB6A02; font-weight:700; }
.cover .doctype { position:absolute; top:72mm; left:20mm; background:#FB6A02; color:#fff;
                  font-weight:700; padding:5px 13px; border-radius:3px; font-size:11pt; letter-spacing:.4px; }
.cover h1 { position:absolute; top:86mm; left:20mm; right:20mm; font-size:30pt; font-weight:300;
            margin:0; line-height:1.15; }
.cover .sub { position:absolute; top:128mm; left:20mm; right:24mm; color:#c7d0e4; font-size:12pt; line-height:1.45; }
.cover .meta { position:absolute; bottom:24mm; left:20mm; right:20mm; color:#dfe4f0; font-size:10.5pt; line-height:1.85; }
.cover .meta b { color:#fff; }
.cover .foot { position:absolute; bottom:12mm; left:20mm; right:20mm; color:#8792ab; font-size:8pt; }

/* ---- stat tiles + severity bar ---- */
.tiles { display:flex; gap:9px; margin:2px 0 14px; }
.tile { flex:1; border:1px solid #E2E5EA; border-radius:5px; padding:10px 6px; text-align:center; }
.tile .n { font-size:25pt; font-weight:300; line-height:1; color:#14213D; }
.tile .l { color:#6B7280; font-size:8.5pt; margin-top:5px; }
.tile.crit .n{color:#C1121F} .tile.high .n{color:#E8590C} .tile.med .n{color:#E0A100} .tile.safe .n{color:#2B8A3E}
.sevbar { display:flex; height:15px; border-radius:3px; overflow:hidden; margin:2px 0; background:#F3F4F6; }
.sevbar span { display:block; }
.sevleg { font-size:8.5pt; color:#6B7280; margin-bottom:16px; }
.sevleg i { font-style:normal; margin-right:12px; }
.sevleg b { display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:4px; vertical-align:baseline; }

/* ---- body typography (JET) ---- */
.body h1 { font-size:16pt; color:#14213D; font-weight:600; border-bottom:2px solid #FB6A02;
           padding-bottom:3px; margin:22px 0 9px; page-break-after:avoid; }
.body h2 { font-size:12.5pt; color:#1E2E52; font-weight:600; margin:15px 0 5px; page-break-after:avoid; }
.body h3 { font-size:11pt; color:#14213D; font-weight:600; margin:13px 0 4px; page-break-after:avoid; }
.body p, .body li { font-size:10.5pt; line-height:1.5; }
.body code { font-family:Consolas,"SF Mono",monospace; font-size:9pt; background:#F3F4F6; padding:1px 4px; border-radius:3px; }
.body pre { background:#F3F4F6; border:1px solid #E2E5EA; border-left:3px solid #FB6A02; border-radius:4px;
            padding:9px 11px; font-size:8.7pt; line-height:1.42; white-space:pre-wrap; word-wrap:break-word;
            overflow-wrap:anywhere; page-break-inside:avoid; }
.body pre code { background:none; padding:0; font-size:8.7pt; }
.body blockquote { background:#eef1f8; border-left:3.5px solid #14213D; margin:9px 0; padding:8px 12px;
                   border-radius:0 3px 3px 0; page-break-inside:avoid; }
.body table { border-collapse:collapse; width:100%; font-size:9.5pt; margin:9px 0; }
.body th { background:#14213D; color:#fff; text-align:left; padding:5px 7px; font-weight:600; }
.body td { border:1px solid #E2E5EA; padding:5px 7px; vertical-align:top; }
.body hr { border:none; border-top:1px solid #E2E5EA; margin:18px 0; }
.badge { display:inline-block; padding:1px 8px; border-radius:3px; color:#fff; font-weight:700; font-size:9pt; }
.badge.CRITICAL{background:#C1121F} .badge.HIGH{background:#E8590C}
.badge.MEDIUM{background:#E0A100} .badge.LOW{background:#6B7280} .badge.SAFE{background:#2B8A3E}
.page-break { page-break-before: always; }
"""


def _sev_snapshot(findings: list[dict]) -> dict:
    out = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        s = (f.get("severity") or "").upper()
        if s in out:
            out[s] += 1
    return out


def _jet_cover(title: str, scope: str, created: str) -> str:
    sub = ("A code-level security assessment across every monitored repository, "
           "with prioritised business impact and full technical detail."
           if scope == "all repositories" else
           f"A code-level security assessment of <b>{html.escape(scope)}</b>, "
           "with prioritised business impact and full technical detail.")
    return (
        '<div class="cover"><div class="band"></div>'
        '<div class="top"><span>JET <span class="accent">/</span> <b>AppSec</b></span>'
        '<span>Continuous Security Scanning</span></div>'
        '<div class="doctype">EXECUTIVE REPORT</div>'
        f'<h1>{html.escape(title)}</h1>'
        f'<div class="sub">{sub}</div>'
        '<div class="meta">'
        '<b>Prepared for:</b>&nbsp; Security Leadership (CISO / CTO) &amp; Engineering Owners<br>'
        f'<b>Date:</b>&nbsp; {html.escape(created or "")}<br>'
        f'<b>Scope:</b>&nbsp; {html.escape(scope)}<br>'
        '<b>Classification:</b>&nbsp; Confidential — internal distribution only</div>'
        '<div class="foot">Generated by security-forge · continuous static analysis. '
        'Findings are point-in-time against each repository\'s default branch.</div>'
        '</div>')


def _jet_tiles(sev: dict, total: int) -> str:
    tiles = [("navy", total, "Open findings"),
             ("crit", sev.get("CRITICAL", 0), "Critical"),
             ("high", sev.get("HIGH", 0), "High"),
             ("med", sev.get("MEDIUM", 0), "Medium")]
    cells = "".join(f'<div class="tile {c}"><div class="n">{n}</div>'
                    f'<div class="l">{l}</div></div>' for c, n, l in tiles)
    # stacked severity bar
    seg = ""
    for s in _SEV_ORDER:
        n = sev.get(s, 0)
        if n and total:
            seg += f'<span style="width:{n / total * 100:.4f}%;background:{_SEV_HEX[s]}"></span>'
    leg = "".join(f'<i><b style="background:{_SEV_HEX[s]}"></b>{s.title()} {sev.get(s, 0)}</i>'
                  for s in _SEV_ORDER if sev.get(s, 0))
    return (f'<div class="tiles">{cells}</div>'
            f'<div class="sevbar">{seg}</div><div class="sevleg">{leg}</div>')


def _jet_body(markdown_text: str) -> str:
    body = _md_to_html(markdown_text)
    # severity words -> pills (as in advisory headings)
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"):
        body = body.replace(f"[{s}]", f'<span class="badge {s}">{s}</span>')
    # start the technical appendix on a fresh page
    body = _re.sub(r'(<h1[^>]*>\s*(?:<[^>]+>\s*)*Technical appendix)',
                   r'<div class="page-break"></div>\1', body, count=1)
    return f'<div class="body">{body}</div>'


def report_html(report: dict) -> str:
    """Full JET-format HTML for a stored report row (cover + tiles + body)."""
    try:
        sev = json.loads(report.get("sev_json") or "{}")
    except (ValueError, TypeError):
        sev = {}
    total = int(report.get("findings_count") or sum(sev.values()) or 0)
    inner = (_jet_cover(report.get("title") or "Security Report",
                        report.get("scope") or "all repositories",
                        (report.get("created") or "")[:10])
             + _jet_tiles(sev, total)
             + _jet_body(report.get("markdown") or "_No content._"))
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{html.escape(report.get('title') or 'report')}</title>"
            f"<style>{_JET_CSS}</style></head><body>{inner}</body></html>")


def report_pdf(report: dict) -> bytes:
    return to_pdf(report_html(report))
