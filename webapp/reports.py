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
