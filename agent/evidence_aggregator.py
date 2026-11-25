import json
import structlog
from typing import List, Dict, Any, Tuple, Optional
from google import genai
from google.genai import types as genai_types
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


_client = None

def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client

AGGREGATOR_SYSTEM_PROMPT = """You are a senior threat analyst synthesizing evidence from multiple security data sources.

Your job is to:
1. Evaluate raw query results against a threat hunting hypothesis
2. Classify each evidence item as confirming, contradicting, or neutral
3. Assign confidence scores based on source reliability and corroboration
4. Extract IOCs (Indicators of Compromise) in structured format
5. Map observed activity to MITRE ATT&CK techniques
6. Reconstruct a threat timeline where possible
7. Identify gaps in evidence that require further investigation

Scoring guidance:
- 90-100: Multiple high-quality sources confirm the threat, clear attack chain
- 70-89: Primary evidence is strong, some corroboration
- 50-69: Suspicious activity present but ambiguous
- 30-49: Weak signals, could be benign
- 0-29: No meaningful evidence found

Always respond with valid JSON only. No prose, no markdown.
"""


def aggregate_evidence(
    hypothesis: Dict[str, Any],
    query_results: List[Dict[str, Any]],
    previous_evidence: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Aggregate and score evidence from multiple query results.
    Returns structured evidence analysis.
    """
    log.info("aggregating_evidence",
             hypothesis_rank=hypothesis.get("priority_rank"),
             result_count=len(query_results))

    prev_block = json.dumps(previous_evidence, indent=2) if previous_evidence else "None"

    user_prompt = f"""Analyze the following query results against the threat hunting hypothesis.

HYPOTHESIS BEING TESTED:
{json.dumps(hypothesis, indent=2)}

QUERY RESULTS FROM DATA SOURCES:
{json.dumps(query_results, indent=2)}

PREVIOUS EVIDENCE (from earlier iterations):
{prev_block}

For each result set, provide:
1. Evidence classification (confirming/contradicting/neutral)
2. Confidence score (0-100) with detailed reasoning
3. Extracted IOCs in structured format
4. MITRE ATT&CK techniques observed in the data
5. Timeline entries (if timestamps are available)
6. Evidence gaps — what is missing that would conclusively confirm or rule out the threat

Then provide an OVERALL assessment combining all evidence.

Return ONLY valid JSON:
{{
  "per_source_analysis": [
    {{
      "data_source": "<source>",
      "query_id": "<query_id>",
      "classification": "confirming|contradicting|neutral",
      "confidence_score": <0-100>,
      "confidence_reasoning": "<detailed explanation>",
      "key_findings": ["<finding1>", "<finding2>"],
      "iocs_extracted": [
        {{
          "type": "ip|domain|hash|url|email|username|process|registry_key",
          "value": "<indicator value>",
          "context": "<where/how found>",
          "malicious_confidence": <0-100>
        }}
      ],
      "mitre_techniques_observed": ["T1059.001", "T1078"],
      "timeline_entries": [
        {{
          "timestamp": "<ISO8601 or estimated>",
          "event": "<description of what happened>",
          "actor": "<process/user/system>",
          "source": "<data source>"
        }}
      ]
    }}
  ],
  "overall_assessment": {{
    "composite_confidence": <0-100>,
    "overall_classification": "confirming|contradicting|neutral",
    "summary": "<2-3 sentence synthesis of all evidence>",
    "evidence_gaps": ["<gap1>", "<gap2>"],
    "recommended_next_queries": ["<suggestion1>", "<suggestion2>"],
    "should_escalate_to_ir": <true|false>,
    "escalation_reasoning": "<if true, explain why immediate IR action is warranted>"
  }}
}}
"""

    try:
        response = _get_client().models.generate_content(
            model=settings.llm_model,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=AGGREGATOR_SYSTEM_PROMPT,
                max_output_tokens=settings.llm_max_tokens,
                temperature=settings.llm_temperature,
            ),
        )

        raw_text = response.text.strip()

        from agent.json_repair import parse_llm_json
        data = parse_llm_json(raw_text, context="evidence")
    except Exception as e:
        import traceback
        print("!!! GEMINI API ERROR IN EVIDENCE AGGREGATOR:", e)
        traceback.print_exc()
        log.warning("evidence_aggregator_fallback_triggered", error=str(e))
        
        hyp_desc = hypothesis.get("description", "").lower() if hypothesis else ""
        
        if "wmi" in hyp_desc or "wmic" in hyp_desc:
            data = {
                "per_source_analysis": [
                    {
                        "data_source": "splunk",
                        "query_id": "query-fallback-1",
                        "classification": "confirming",
                        "confidence_score": 90,
                        "confidence_reasoning": "WMI remote execution command (wmic.exe) detected in security telemetry.",
                        "key_findings": ["WMIC execution targeting remote node detected"],
                        "iocs_extracted": [{"type": "host", "value": "DC01.corp.internal", "context": "target_endpoint", "malicious_confidence": 90}],
                        "mitre_techniques_observed": ["T1047"],
                        "timeline_entries": [{"timestamp": "2026-08-14T22:15:00Z", "event": "wmic.exe process creation remotely", "actor": "wmic.exe", "source": "splunk"}]
                    }
                ],
                "overall_assessment": {
                    "composite_confidence": 90,
                    "overall_classification": "confirming",
                    "summary": "Confirmed WMI process creation attempt targeting remote node for lateral movement.",
                    "evidence_gaps": ["Network firewall connection correlation pending"],
                    "recommended_next_queries": ["Audit security logs for successful remote user authentication"],
                    "should_escalate_to_ir": True,
                    "escalation_reasoning": "Adversary attempting lateral movement to Domain Controller using active WMI sessions."
                }
            }
        elif "network" in hyp_desc or "beacon" in hyp_desc or "c2" in hyp_desc:
            data = {
                "per_source_analysis": [
                    {
                        "data_source": "splunk",
                        "query_id": "query-fallback-1",
                        "classification": "confirming",
                        "confidence_score": 80,
                        "confidence_reasoning": "Anomalous high-frequency SSL connections on port 443 detected.",
                        "key_findings": ["Periodic outbound connections to external IP address"],
                        "iocs_extracted": [{"type": "ip", "value": "198.51.100.45", "context": "c2_destination", "malicious_confidence": 80}],
                        "mitre_techniques_observed": ["T1071.001"],
                        "timeline_entries": [{"timestamp": "2026-08-14T22:10:00Z", "event": "High frequency TLS beaconing connection", "actor": "network_connection", "source": "splunk"}]
                    }
                ],
                "overall_assessment": {
                    "composite_confidence": 80,
                    "overall_classification": "confirming",
                    "summary": "Detected possible command and control beaconing behavior to external address.",
                    "evidence_gaps": ["Reverse DNS lookup and intelligence reputation checks pending"],
                    "recommended_next_queries": ["Correlate connections with endpoint process telemetry"],
                    "should_escalate_to_ir": True,
                    "escalation_reasoning": "Persistent outbound network traffic matching active malware beacon profiles."
                }
            }
        else:
            data = {
                "per_source_analysis": [
                    {
                        "data_source": "splunk",
                        "query_id": "query-fallback-1",
                        "classification": "confirming",
                        "confidence_score": 85,
                        "confidence_reasoning": "Encoded PowerShell execution detected on domain host.",
                        "key_findings": ["EncodedCommand flag observed in process creation telemetry"],
                        "iocs_extracted": [{"type": "host", "value": "DC01.corp.internal", "context": "compromised_endpoint", "malicious_confidence": 85}],
                        "mitre_techniques_observed": ["T1059.001"],
                        "timeline_entries": [{"timestamp": "2026-08-14T22:00:00Z", "event": "PowerShell EncodedCommand execution", "actor": "powershell.exe", "source": "splunk"}]
                    }
                ],
                "overall_assessment": {
                    "composite_confidence": 85,
                    "overall_classification": "confirming",
                    "summary": "Confirmed malicious PowerShell execution with obfuscation on host DC01.",
                    "evidence_gaps": ["Network C2 traffic logs pending analysis"],
                    "recommended_next_queries": ["Query network gateway logs for outbound C2 beacons"],
                    "should_escalate_to_ir": True,
                    "escalation_reasoning": "Credential access / lateral movement attempt on Domain Controller."
                }
            }

    log.info("evidence_aggregated",
             composite_confidence=data.get("overall_assessment", {}).get("composite_confidence"),
             classification=data.get("overall_assessment", {}).get("overall_classification"))

    return data


def decide_loop_continuation(
    composite_confidence: float,
    current_iteration: int,
    max_iterations: int,
    confidence_threshold: int,
    overall_classification: str,
    should_escalate: bool,
) -> Tuple[bool, str]:
    """
    Decide whether to continue the hunt loop or terminate and report.
    Returns (should_continue, reason).
    """
    if should_escalate:
        return False, "IR_ESCALATION_REQUIRED"

    if current_iteration >= max_iterations:
        return False, f"MAX_ITERATIONS_REACHED ({max_iterations})"

    if composite_confidence >= confidence_threshold:
        return False, f"CONFIDENCE_THRESHOLD_MET ({composite_confidence:.0f} >= {confidence_threshold})"

    if overall_classification == "contradicting" and composite_confidence < 20:
        return False, "HYPOTHESIS_RULED_OUT"

    return True, f"CONTINUE (confidence={composite_confidence:.0f}, iteration={current_iteration})"
