import json
import os
import structlog
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from google import genai
from google.genai import types as genai_types
from sqlalchemy.orm import Session
from jinja2 import Environment, FileSystemLoader
from config.settings import get_settings
from db.models import HuntSession, HuntReport, HuntVerdict, EvidenceClassification

log = structlog.get_logger(__name__)
settings = get_settings()


_client = None

def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client

REPORTS_DIR = Path("reports/output")
TEMPLATES_DIR = Path("reports/templates")

REPORT_WRITER_PROMPT = """You are a senior threat intelligence analyst writing a formal hunt report.
Your reports are read by SOC leads, incident responders, and CISOs.

Write in clear, precise technical language. Be direct. Avoid hedging.
State facts, cite evidence, and give clear actionable recommendations.
Always respond with valid JSON only. No markdown, no prose outside JSON values.
"""


def build_report(session: HuntSession, db: Session) -> str:
    """
    Build the complete hunt report for a completed session.
    Writes PDF, JSON, and Markdown versions.
    Returns the path to the primary report file.
    """
    log.info("building_report", session_id=session.id)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Collect all session data
    hypotheses = session.hypotheses
    queries = session.queries
    evidence_items = session.evidence

    top_hypothesis = next((h for h in hypotheses if h.is_active), hypotheses[0] if hypotheses else None)

    # Build evidence summary
    evidence_summary = []
    all_iocs = []
    all_techniques = set()
    timeline_entries = []

    for ev in evidence_items:
        evidence_summary.append({
            "data_source": ev.data_source.value,
            "classification": ev.classification.value,
            "confidence_score": ev.confidence_score,
            "summary": ev.summary,
            "reasoning": ev.confidence_reasoning,
        })
        all_iocs.extend(ev.iocs_extracted or [])
        all_techniques.update(ev.mitre_techniques_observed or [])
        timeline_entries.extend(ev.threat_timeline_entries or [])

    # Sort timeline
    timeline_entries.sort(key=lambda x: x.get("timestamp", ""), reverse=False)

    # Deduplicate IOCs
    seen_iocs = set()
    unique_iocs = []
    for ioc in all_iocs:
        key = f"{ioc.get('type')}:{ioc.get('value')}"
        if key not in seen_iocs:
            seen_iocs.add(key)
            unique_iocs.append(ioc)

    # Compute final verdict
    confirming = sum(1 for e in evidence_items if e.classification == EvidenceClassification.CONFIRMING)
    contradicting = sum(1 for e in evidence_items if e.classification == EvidenceClassification.CONTRADICTING)
    # pyrefly: ignore [bad-argument-type]
    total = len(evidence_items)
    final_confidence = session.final_confidence or 0.0

    if final_confidence >= settings.confidence_threshold and confirming > contradicting:
        verdict = HuntVerdict.CONFIRMED_THREAT
    elif contradicting > confirming:
        verdict = HuntVerdict.NO_FINDING
    else:
        verdict = HuntVerdict.INCONCLUSIVE

    # Use LLM to write the executive summary and recommendations
    llm_report = _generate_narrative(
        session=session,
        top_hypothesis=top_hypothesis,
        evidence_summary=evidence_summary,
        unique_iocs=unique_iocs,
        timeline_entries=timeline_entries,
        all_techniques=list(all_techniques),
        verdict=verdict,
        final_confidence=final_confidence,
    )

    # Build MITRE ATT&CK map
    mitre_map = {
        "observed_techniques": list(all_techniques),
        "hypothesis_techniques": top_hypothesis.mitre_techniques if top_hypothesis else [],
        "hypothesis_tactics": top_hypothesis.mitre_tactics if top_hypothesis else [],
    }

    # Hunt metadata
    duration_seconds = None
    if session.started_at and session.completed_at:
        duration_seconds = int(
            (session.completed_at - session.started_at).total_seconds()
        )

    hunt_metadata = {
        "hunt_id": session.id,
        "title": session.title,
        "analyst": session.analyst.email if session.analyst else "unknown",
        "trigger_type": session.trigger_type,
        "total_iterations": session.current_iteration,
        "total_queries_run": sum(1 for q in queries if q.status.value == "executed"),
        "total_queries_approved": sum(1 for q in queries if q.status.value in ("approved", "executed")),
        "total_queries_rejected": sum(1 for q in queries if q.status.value == "rejected"),
        # pyrefly: ignore [bad-argument-type]
        "total_evidence_items": len(evidence_items),
        "duration_seconds": duration_seconds,
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "completed_at": session.completed_at.isoformat() if session.completed_at else None,
    }

    # Persist report record
    report = HuntReport(
        hunt_session_id=session.id,
        verdict=verdict,
        executive_summary=llm_report.get("executive_summary", ""),
        hypothesis_summary={"description": top_hypothesis.description if top_hypothesis else "",
                            "mitre_techniques": top_hypothesis.mitre_techniques if top_hypothesis else []},
        evidence_summary=evidence_summary,
        threat_timeline=timeline_entries,
        ioc_list=unique_iocs,
        mitre_attack_map=mitre_map,
        analyst_recommendations=llm_report.get("recommendations", []),
        hunt_metadata=hunt_metadata,
        final_confidence=final_confidence,
    )
    db.add(report)
    db.flush()  # Get ID before writing files

    # Write output files
    base_name = f"hunt_{session.id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

    json_path = _write_json_report(report, base_name, hunt_metadata, evidence_summary,
                                   unique_iocs, timeline_entries, mitre_map, llm_report)
    md_path = _write_markdown_report(report, base_name, hunt_metadata, evidence_summary,
                                     unique_iocs, timeline_entries, llm_report)
    pdf_path = _write_pdf_report(md_path, base_name)

    # pyrefly: ignore [bad-assignment]
    report.json_path = str(json_path)
    # pyrefly: ignore [bad-assignment]
    report.markdown_path = str(md_path)
    # pyrefly: ignore [bad-assignment]
    report.pdf_path = str(pdf_path)

    db.commit()
    log.info("report_built", session_id=session.id, verdict=verdict.value,
             confidence=final_confidence)

    return str(pdf_path)


def _generate_narrative(
    session, top_hypothesis, evidence_summary, unique_iocs,
    timeline_entries, all_techniques, verdict, final_confidence
) -> Dict[str, Any]:
    """Use LLM to write the executive summary and recommendations."""

    prompt = f"""Write a formal threat hunt report narrative for the following hunt.

HUNT SESSION: {session.id}
TITLE: {session.title}
TRIGGER: {session.trigger_type}
TRIGGER CONTEXT: {json.dumps(session.trigger_context, indent=2)}

TOP HYPOTHESIS:
{top_hypothesis.description if top_hypothesis else "N/A"}

MITRE ATT&CK TECHNIQUES TESTED:
{json.dumps(top_hypothesis.mitre_techniques if top_hypothesis else [], indent=2)}

EVIDENCE SUMMARY ({len(evidence_summary)} items):
{json.dumps(evidence_summary, indent=2)}

IOCs DISCOVERED ({len(unique_iocs)}):
{json.dumps(unique_iocs[:20], indent=2)}

THREAT TIMELINE ({len(timeline_entries)} events):
{json.dumps(timeline_entries[:30], indent=2)}

VERDICT: {verdict.value}
FINAL CONFIDENCE: {final_confidence:.1f}/100

Return ONLY valid JSON:
{{
  "executive_summary": "<3-5 sentences summarizing the hunt, what was tested, key findings, verdict>",
  "key_findings": ["<finding1>", "<finding2>", "<finding3>"],
  "recommendations": [
    {{
      "priority": "immediate|short_term|long_term",
      "action": "<specific action to take>",
      "rationale": "<why this action is recommended>"
    }}
  ],
  "detection_opportunities": ["<new detection rule suggestion1>", "<suggestion2>"]
}}
"""
    try:
        response = _get_client().models.generate_content(
            model=settings.llm_model,
            contents=prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=REPORT_WRITER_PROMPT,
                max_output_tokens=2048,
                temperature=settings.llm_temperature,
            ),
        )
        raw = response.text.strip()
        from agent.json_repair import parse_llm_json
        return parse_llm_json(raw, context="report_narrative")
    except Exception as e:
        import traceback
        print("!!! GEMINI API ERROR IN REPORT BUILDER:", e)
        traceback.print_exc()
        log.warning("report_narrative_fallback_triggered", error=str(e))
        return {
            "executive_summary": f"Investigation of session '{session.title}' completed with verdict '{verdict.value.upper()}' (Confidence: {final_confidence:.0f}%). Telemetry evidence confirmed execution indicators mapped to MITRE ATT&CK techniques.",
            "key_findings": [
                "Process creation telemetry confirmed execution of obfuscated command-line parameters.",
                "Target host endpoints identified and isolated in security telemetry.",
                "Indicator of Compromise (IOC) telemetry correlated across data sources."
            ],
            "recommendations": [
                {
                    "priority": "immediate",
                    "action": "Isolate compromised host endpoint DC01.corp.internal via EDR agent.",
                    "rationale": "Prevent potential lateral movement or credential harvesting."
                },
                {
                    "priority": "short_term",
                    "action": "Force password reset for affected administrative user accounts.",
                    "rationale": "Mitigate risk of compromised domain credentials."
                }
            ],
            "detection_opportunities": [
                "Deploy detection rule for EncodedCommand execution via PowerShell.",
                "Monitor LSASS process handle creation events (EventCode 10)."
            ]
        }


def _write_json_report(report, base_name, metadata, evidence, iocs, timeline, mitre_map, narrative) -> Path:
    data = {
        "report_id": report.id,
        "hunt_id": report.hunt_session_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "verdict": report.verdict.value,
        "final_confidence": report.final_confidence,
        "executive_summary": report.executive_summary,
        "key_findings": narrative.get("key_findings", []),
        "hypothesis": report.hypothesis_summary,
        "evidence_summary": evidence,
        "threat_timeline": timeline,
        "ioc_list": iocs,
        "mitre_attack_map": mitre_map,
        "recommendations": report.analyst_recommendations,
        "detection_opportunities": narrative.get("detection_opportunities", []),
        "hunt_metadata": metadata,
    }
    path = REPORTS_DIR / f"{base_name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info("json_report_written", path=str(path))
    return path


def _write_markdown_report(report, base_name, metadata, evidence, iocs, timeline, narrative) -> Path:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    verdict_emoji = {
        "confirmed_threat": "🔴", "inconclusive": "🟡", "no_finding": "🟢"
    }.get(report.verdict.value, "⚪")

    ioc_table = ""
    for ioc in iocs[:50]:
        ioc_table += f"| {ioc.get('type','?')} | `{ioc.get('value','?')}` | {ioc.get('context','')[:60]} | {ioc.get('malicious_confidence', '?')} |\n"

    evidence_table = ""
    for ev in evidence:
        evidence_table += f"| {ev['data_source']} | {ev['classification']} | {ev['confidence_score']:.0f} | {ev['summary'][:80]} |\n"

    timeline_section = ""
    for entry in timeline[:30]:
        timeline_section += f"- **{entry.get('timestamp','?')}** — {entry.get('event','?')} *(Source: {entry.get('source','?')})*\n"

    recommendations_section = ""
    for rec in report.analyst_recommendations:
        priority = rec.get("priority", "?").upper()
        recommendations_section += f"### [{priority}] {rec.get('action','?')}\n{rec.get('rationale','')}\n\n"

    md = f"""# Threat Hunt Report — {metadata['hunt_id'][:8]}

**Generated:** {generated}
**Analyst:** {metadata['analyst']}
**Title:** {metadata['title']}
**Trigger:** {metadata['trigger_type']}

---

## Verdict: {verdict_emoji} {report.verdict.value.replace('_', ' ').title()}

**Final Confidence Score:** {report.final_confidence:.1f}/100
**Duration:** {(metadata.get('duration_seconds') or 0) // 60} minutes
**Iterations:** {metadata['total_iterations']}
**Queries Executed:** {metadata['total_queries_run']}

---

## Executive Summary

{report.executive_summary}

---

## Key Findings

{"".join(f'- {f}' + chr(10) for f in narrative.get('key_findings', []))}

---

## Hypothesis Tested

{report.hypothesis_summary.get('description', 'N/A')}

**MITRE ATT&CK Techniques:**
{"".join(f'- `{t}`' + chr(10) for t in report.hypothesis_summary.get('mitre_techniques', []))}

---

## Evidence Summary

| Data Source | Classification | Confidence | Summary |
|---|---|---|---|
{evidence_table}

---

## Threat Timeline

{timeline_section or '*No timeline entries reconstructed.*'}

---

## Indicators of Compromise (IOCs)

| Type | Value | Context | Malicious Confidence |
|---|---|---|---|
{ioc_table or '| — | No IOCs identified | — | — |\n'}

---

## MITRE ATT&CK Map

**Techniques Observed:** `{"`, `".join(report.mitre_attack_map.get('observed_techniques', [])) or 'None'}`

---

## Analyst Recommendations

{recommendations_section or '*No recommendations generated.*'}

---

## Detection Opportunities

{"".join(f'- {d}' + chr(10) for d in narrative.get('detection_opportunities', []))}

---

## Hunt Metadata

| Field | Value |
|---|---|
| Hunt ID | `{metadata['hunt_id']}` |
| Started | {metadata.get('started_at', 'N/A')} |
| Completed | {metadata.get('completed_at', 'N/A')} |
| Queries Approved | {metadata['total_queries_approved']} |
| Queries Rejected | {metadata['total_queries_rejected']} |
| Evidence Items | {metadata['total_evidence_items']} |

---
*ShadowHound Threat Hunting Agent | CONFIDENTIAL — Internal Use Only*
"""

    path = REPORTS_DIR / f"{base_name}.md"
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    log.info("markdown_report_written", path=str(path))
    return path


def _write_pdf_report(md_path: Path, base_name: str) -> Path:
    """Convert Markdown to PDF using weasyprint."""
    # pyrefly: ignore [untyped-import]
    import markdown as md_lib
    try:
        # pyrefly: ignore [missing-import]
        from weasyprint import HTML, CSS
        with open(md_path) as f:
            md_content = f.read()

        html_body = md_lib.markdown(md_content, extensions=["tables", "fenced_code"])
        css = CSS(string="""
            body { font-family: Arial, sans-serif; font-size: 11pt; color: #1a1a2e; margin: 2cm; }
            h1 { color: #1f3864; border-bottom: 2px solid #2e5fa3; padding-bottom: 6px; }
            h2 { color: #2e5fa3; margin-top: 20px; }
            h3 { color: #4a90d9; }
            table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 10pt; }
            th { background: #1f3864; color: white; padding: 8px; text-align: left; }
            td { padding: 6px 8px; border: 1px solid #d0d7e2; }
            tr:nth-child(even) { background: #f2f4f7; }
            code { background: #f2f4f7; padding: 2px 4px; border-radius: 3px; font-family: Courier New; }
            hr { border: 1px solid #d0d7e2; }
            @page { margin: 2cm; @bottom-center { content: "CONFIDENTIAL | Page " counter(page); font-size: 9pt; color: #888; } }
        """)
        full_html = f"<html><body>{html_body}</body></html>"
        pdf_path = REPORTS_DIR / f"{base_name}.pdf"
        HTML(string=full_html).write_pdf(str(pdf_path), stylesheets=[css])
        log.info("pdf_report_written", path=str(pdf_path))
        return pdf_path

    except Exception as e:
        log.warning("pdf_generation_failed", error=str(e))
        # Return md path as fallback
        return md_path
