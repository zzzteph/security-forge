"""Executive-report generation — the job behind the "Generate report" button.

A report is written in TWO halves:

  1. Narrative (AI).  A one-shot LiteLLM completion turns the current findings +
     the repo's operator context (focus areas / what is NOT an issue / triage
     hints) into a leadership-readable story: executive summary, what was checked,
     key risks, and recommendations. No code here.
  2. Technical appendix (deterministic).  Every finding is rendered as the same
     GHSA-style advisory the pipeline already produces — code traces in code
     blocks and the PoC verbatim — so the technical detail is always accurate and
     never hallucinated.

The two are concatenated into one markdown artifact stored on the report row;
reports.report_html() renders it in the JET format (navy/orange cover, severity
pills, stat tiles, callout boxes) for the PDF download.

The report summarises findings already in the DB, so it runs as a direct LiteLLM
call (fast, no repo checkout) using the global AI configuration in Settings.
"""
from __future__ import annotations

import json
import os

import db
import reports

# Triage dispositions that should NOT appear as live risk in a shareable report.
_EXCLUDE_TRIAGE = {"false_positive", "duplicate"}
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

_SYSTEM = (
    "You are a principal application-security consultant writing a concise, "
    "board-level security report for a CISO, CTO and engineering managers. "
    "You are given machine-generated findings from a static code review. Write in "
    "plain, confident business English — explain impact in terms of data, money, "
    "customers and compliance, not jargon. Be specific and reference findings by "
    "their title and severity, but DO NOT include code, stack traces, file paths "
    "or proof-of-concept snippets — a separate technical appendix carries all of "
    "that. Do not invent findings, CVEs or numbers that are not supported by the "
    "input. Respect the operator's scope notes as authoritative (if they say "
    "something is not an issue, treat it as out of scope).\n\n"
    "Output GitHub-flavoured Markdown with EXACTLY these sections, in order:\n"
    "## Executive summary\n"
    "(2–4 sentences: the overall posture and the single biggest risk.)\n"
    "> **The one thing to take away:** (one sentence, the headline decision.)\n"
    "## What was checked\n"
    "(Scope and method: what repositories/areas were reviewed, the kinds of "
    "weakness looked for, and any operator focus areas or explicit exclusions.)\n"
    "## Key risks\n"
    "(Group the findings into a few themes. For each, plain-English business "
    "impact and which findings drive it. Order by severity.)\n"
    "## Recommendations & ideas\n"
    "(A numbered, prioritised action list — what to fix now vs. next, plus "
    "systemic/'paved-road' ideas that would prevent whole classes of these bugs.)\n"
)


def _report_findings(repo_id: int | None) -> list[dict]:
    """Open findings for the report scope, minus false-positives/duplicates,
    most-severe first."""
    rows = db.list_findings(status="open", repo_id=repo_id)
    rows = [f for f in rows if (f.get("triage") or "unset") not in _EXCLUDE_TRIAGE]
    rows.sort(key=lambda r: _SEV_RANK.get((r.get("severity") or "").upper(), 0), reverse=True)
    return rows


def _compact(f: dict) -> dict:
    """The slice of a finding the narrative model needs (no code / PoC)."""
    loc = f.get("file") or ""
    if loc and f.get("line"):
        loc += f":{f['line']}"
    return {k: v for k, v in {
        "severity": (f.get("severity") or "").upper(),
        "title": f.get("title"),
        "project": f.get("slug"),
        "location": loc,
        "cwe": f.get("cwe"),
        "category": f.get("category"),
        "reachability": f.get("reachability"),
        "impact": (f.get("impact") or "")[:600],
        "summary": (f.get("description") or "")[:600],
        "triage": (f.get("triage") if (f.get("triage") or "unset") != "unset" else None),
    }.items() if v}


def _llm_narrative(findings: list[dict], scope: str, context: str,
                   triage_ctx: str, cfg: dict) -> tuple[str, str, float]:
    """Return (narrative_markdown, model_used, cost_usd). Raises on misconfig /
    transport error so the caller can mark the report 'error' with the reason."""
    model = (cfg.get("model") or "").strip()
    if not model:
        raise RuntimeError("No AI model is configured. Set a LiteLLM model in "
                           "Settings → AI configuration (e.g. openai/gpt-5, "
                           "anthropic/claude-sonnet-5, gemini/gemini-2.5-pro).")
    # Provider keys / base URLs from the global config are env-scoped for LiteLLM.
    for e in (cfg.get("env") or []):
        try:
            k = (e.get("key") or "").strip()
            if k and not os.environ.get(k):
                os.environ[k] = str(e.get("value", ""))
        except (AttributeError, TypeError):
            pass

    detailed = findings[:60]
    payload = {
        "scope": scope,
        "totals": {"open_findings": len(findings),
                   "by_severity": reports._sev_snapshot(findings)},
        "operator_context": context or "(none provided)",
        "human_triage_notes": triage_ctx or "(none)",
        "findings": [_compact(f) for f in detailed],
        "note": (f"{len(findings) - len(detailed)} lower-severity findings omitted "
                 "from this list but included in the appendix."
                 if len(findings) > len(detailed) else ""),
    }
    user = ("Write the report for this scope. Findings and context follow as JSON.\n\n"
            + json.dumps(payload, ensure_ascii=False, indent=2))

    import litellm
    litellm.drop_params = True
    kwargs: dict = {"model": model,
                    "messages": [{"role": "system", "content": _SYSTEM},
                                 {"role": "user", "content": user}]}
    base = (cfg.get("base_url") or "").strip()
    if base:
        kwargs["api_base"] = base
        if not model.startswith("openai/"):     # OpenAI-compatible gateway convention
            kwargs["model"] = "openai/" + model
    temp = cfg.get("temperature")
    if temp not in (None, ""):
        try:
            kwargs["temperature"] = float(temp)
        except (TypeError, ValueError):
            pass
    key = (os.environ.get("SECFORGE_LLM_API_KEY") or "").strip()
    if key:
        kwargs["api_key"] = key

    resp = litellm.completion(**kwargs)
    text = (resp.choices[0].message.content or "").strip()
    if not text:
        raise RuntimeError("The model returned an empty report.")
    cost = 0.0
    try:
        cost = float(litellm.completion_cost(completion_response=resp) or 0.0)
    except Exception:  # noqa: BLE001  (cost is best-effort)
        cost = 0.0
    return text, kwargs["model"], cost


def _assemble(narrative: str, findings: list[dict]) -> str:
    # The renderer starts the appendix on a fresh page (it keys off this H1), so no
    # page-break HTML is embedded here — the stored markdown stays clean for the
    # .md download.
    parts = [narrative.strip(), "\n\n",
             "# Technical appendix — findings, traces & PoCs\n\n",
             "_Each finding below is reproduced in full: severity, code trace and "
             "the proof-of-concept, for the engineering owner. Ordered most-severe "
             "first._\n\n"]
    if not findings:
        parts.append("_No open findings met the reporting bar._\n")
    for f in findings:
        parts.append(reports.advisory_markdown(f))
        parts.append("\n\n")
    return "".join(parts)


def run_report(report_id: int) -> None:
    """Build one report end to end and fold the result onto its row. Never raises
    — failures land as status='error' with a human-readable reason."""
    rep = db.get_report(report_id)
    if not rep:
        return
    db.update_report(report_id, status="running", started=db._now())
    repo_id = rep.get("repo_id")
    try:
        findings = _report_findings(repo_id)
        sev = reports._sev_snapshot(findings)
        context = ""
        triage_ctx = ""
        if repo_id:
            r = db.get_repo(repo_id)
            context = (r.get("context") or "").strip() if r else ""
            try:
                triage_ctx = db.triage_context(repo_id) or ""
            except Exception:  # noqa: BLE001
                triage_ctx = ""
        cfg = db.get_setting("defaults", {}) or {}
        narrative, model, cost = _llm_narrative(
            findings, rep.get("scope") or "all repositories", context, triage_ctx, cfg)
        markdown = _assemble(narrative, findings)
        summary = (f"{len(findings)} open finding(s): "
                   + ", ".join(f"{sev[s]} {s.lower()}" for s in reports._SEV_ORDER if sev.get(s))
                   ) if findings else "No open findings met the reporting bar."
        db.update_report(report_id, status="done", finished=db._now(),
                         markdown=markdown, summary=summary, model=model,
                         cost_usd=cost, findings_count=len(findings),
                         sev_json=json.dumps(sev), error=None)
    except Exception as e:  # noqa: BLE001  (report a clean failure, don't crash the worker)
        db.update_report(report_id, status="error", finished=db._now(),
                         error=str(e)[:800])
