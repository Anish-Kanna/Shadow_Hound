import json
import structlog
from typing import List, Dict, Any, Optional
from google import genai
from google.genai import types as genai_types
from config.settings import get_settings
from db.models import DataSource

log = structlog.get_logger(__name__)
settings = get_settings()


_client = None

def _get_client():
    global _client
    if _client is None:
        _client = genai.Client(api_key=settings.gemini_api_key)
    return _client

MITRE_TACTICS = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery", "TA0008": "Lateral Movement",
    "TA0009": "Collection", "TA0010": "Exfiltration", "TA0011": "Command and Control",
    "TA0040": "Impact", "TA0042": "Resource Development", "TA0043": "Reconnaissance",
}

SYSTEM_PROMPT = """You are an expert threat hunter with 15 years of experience in enterprise security operations.
You specialize in hypothesis-driven threat hunting using the MITRE ATT&CK framework.

Your task is to generate structured, actionable threat hunting hypotheses based on:
- Trigger context (analyst request, threat intel, scheduled scan)
- Environmental context (what data sources are available)
- Threat intelligence feeds
- MITRE ATT&CK coverage gaps

Always respond with valid JSON only. No prose, no markdown, no code fences.
Every hypothesis must be specific, testable, and tied to observable indicators.
"""

HYPOTHESIS_SCHEMA = {
    "type": "object",
    "required": ["hypotheses"],
    "properties": {
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "description", "mitre_tactics", "mitre_techniques",
                    "priority_rank", "priority_label", "intel_sources",
                    "suggested_data_sources", "initial_query_templates"
                ],
                "properties": {
                    "description": {"type": "string"},
                    "mitre_tactics": {"type": "array", "items": {"type": "string"}},
                    "mitre_techniques": {"type": "array", "items": {"type": "string"}},
                    "priority_rank": {"type": "integer", "minimum": 1, "maximum": 5},
                    "priority_label": {"type": "string", "enum": ["high", "medium", "low"]},
                    "intel_sources": {"type": "array", "items": {"type": "string"}},
                    "suggested_data_sources": {"type": "array", "items": {"type": "string"}},
                    "initial_query_templates": {"type": "object"},
                }
            }
        }
    }
}


def generate_hypotheses(
    trigger_type: str,
    trigger_context: Dict[str, Any],
    available_data_sources: List[str],
    recent_intel: List[Dict[str, Any]],
    previous_hypotheses: Optional[List[Dict[str, Any]]] = None,
    evidence_so_far: Optional[List[Dict[str, Any]]] = None,
    iteration: int = 1,
) -> List[Dict[str, Any]]:
    """
    Generate ranked threat hunting hypotheses using the LLM.

    On iteration > 1, refines hypotheses based on accumulated evidence.
    """
    log.info("generating_hypotheses", trigger_type=trigger_type, iteration=iteration)

    intel_block = json.dumps(recent_intel, indent=2) if recent_intel else "No recent intel provided."
    prev_block = json.dumps(previous_hypotheses, indent=2) if previous_hypotheses else "None"
    evidence_block = json.dumps(evidence_so_far, indent=2) if evidence_so_far else "None"

    if iteration == 1:
        user_prompt = f"""Generate 3-5 ranked threat hunting hypotheses for the following context.

TRIGGER TYPE: {trigger_type}
TRIGGER CONTEXT:
{json.dumps(trigger_context, indent=2)}

AVAILABLE DATA SOURCES: {", ".join(available_data_sources)}

RECENT THREAT INTELLIGENCE:
{intel_block}

MITRE ATT&CK TACTICS REFERENCE:
{json.dumps(MITRE_TACTICS, indent=2)}

For each hypothesis:
1. Write a specific, testable description of the suspected adversary behavior
2. Map to MITRE ATT&CK tactics and techniques (use exact IDs e.g. T1059.001)
3. Assign priority based on environmental relevance and intel corroboration
4. List which data sources are most likely to contain evidence
5. Provide initial query templates for each data source (use {{PLACEHOLDER}} for dynamic values)

For query templates:
- CrowdStrike/Defender: use KQL syntax
- Splunk: use SPL syntax
- MISP/VirusTotal: use indicator lookup patterns

Return ONLY valid JSON matching this schema:
{json.dumps(HYPOTHESIS_SCHEMA, indent=2)}
"""
    else:
        user_prompt = f"""You are on hunting iteration {iteration}. Refine your hypotheses based on evidence collected so far.

ORIGINAL TRIGGER: {trigger_type}
TRIGGER CONTEXT:
{json.dumps(trigger_context, indent=2)}

PREVIOUS HYPOTHESES:
{prev_block}

EVIDENCE COLLECTED SO FAR:
{evidence_block}

AVAILABLE DATA SOURCES: {", ".join(available_data_sources)}

Instructions:
1. If evidence strongly confirms a hypothesis, keep it as #1 with updated query templates targeting deeper investigation
2. If evidence contradicts a hypothesis, deprioritize or remove it
3. Generate new hypotheses if evidence suggests unexplored threat vectors
4. Focus on gaps — what evidence is missing to confirm or rule out the threat?

Return ONLY valid JSON matching this schema:
{json.dumps(HYPOTHESIS_SCHEMA, indent=2)}
"""

    try:
        response = _get_client().models.generate_content(
            model=settings.llm_model,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                max_output_tokens=1024,
                temperature=settings.llm_temperature,
            ),
        )

        raw_text = response.text.strip()

        from agent.json_repair import parse_llm_json
        data = parse_llm_json(raw_text, context="hypothesis")

        hypotheses = data.get("hypotheses", [])
        log.info("hypotheses_generated", count=len(hypotheses), iteration=iteration)
        return hypotheses
    except ValueError as ve:
        log.error("hypothesis_json_parse_error", error=str(ve))
        raise ValueError(f"LLM returned invalid JSON for hypotheses: {ve}") from ve
    except Exception as e:
        import traceback
        print("!!! GEMINI API ERROR IN BACKEND API:", e)
        traceback.print_exc()
        log.warning("gemini_api_fallback_triggered", error=str(e))
        desc = trigger_context.get("description", "").lower() if trigger_context else ""
        
        if "wmi" in desc or "wmic" in desc:
            return [
                {
                    "description": "Adversary utilizing WMI command-line utility (wmic.exe) for lateral movement and remote execution",
                    "mitre_tactics": ["TA0002", "TA0008"],
                    "mitre_techniques": ["T1047"],
                    "priority_rank": 1,
                    "priority_label": "high",
                    "intel_sources": ["internal_telemetry"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk", "crowdstrike"],
                    "initial_query_templates": {
                        "splunk": "index=* EventCode=4688 Image=*wmic.exe CommandLine=*node*",
                        "crowdstrike": "event_simpleName=ProcessRollup2 ImageFileName=*wmic.exe"
                    }
                },
                {
                    "description": "Adversary abusing WMI provider host process (WmiPrvSE.exe) to spawn child processes remotely",
                    "mitre_tactics": ["TA0002"],
                    "mitre_techniques": ["T1047"],
                    "priority_rank": 2,
                    "priority_label": "medium",
                    "intel_sources": ["internal_telemetry"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk"],
                    "initial_query_templates": {
                        "splunk": "index=* EventCode=4688 ParentImage=*WmiPrvSE.exe"
                    }
                }
            ]
        elif "network" in desc or "beacon" in desc or "c2" in desc or "port" in desc:
            return [
                {
                    "description": "Adversary establishing command and control channel via encrypted HTTPS beaconing traffic",
                    "mitre_tactics": ["TA0011"],
                    "mitre_techniques": ["T1071.001"],
                    "priority_rank": 1,
                    "priority_label": "high",
                    "intel_sources": ["internal_telemetry", "threat_intel"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk", "crowdstrike"],
                    "initial_query_templates": {
                        "splunk": "index=network dest_port=443 | stats count by src_ip, dest_ip | filter count > 100",
                        "crowdstrike": "event_simpleName=NetworkConnect dest_port=443"
                    }
                },
                {
                    "description": "Adversary performing network service scanning or internal reconnaissance of AD assets",
                    "mitre_tactics": ["TA0007"],
                    "mitre_techniques": ["T1046"],
                    "priority_rank": 2,
                    "priority_label": "medium",
                    "intel_sources": ["internal_telemetry"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk"],
                    "initial_query_templates": {
                        "splunk": "index=firewall action=blocked | stats dc(dest_port) by src_ip | filter dc_dest_port > 20"
                    }
                }
            ]
        else:
            return [
                {
                    "description": f"Adversary executing malicious PowerShell/command scripts: {trigger_context.get('description', 'Suspicious activity detected on host') if trigger_context else 'Suspicious process execution'}",
                    "mitre_tactics": ["TA0002", "TA0008"],
                    "mitre_techniques": ["T1059.001", "T1003.001"],
                    "priority_rank": 1,
                    "priority_label": "high",
                    "intel_sources": ["internal_telemetry"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk", "crowdstrike"],
                    "initial_query_templates": {
                        "splunk": "index=* EventCode=4688 CommandLine=*powershell*",
                        "crowdstrike": "event_simpleName=ProcessRollup2 ImageFileName=*powershell.exe"
                    }
                },
                {
                    "description": "Adversary attempting credential dumping or privilege escalation via LSASS memory access",
                    "mitre_tactics": ["TA0006"],
                    "mitre_techniques": ["T1003.001"],
                    "priority_rank": 2,
                    "priority_label": "high",
                    "intel_sources": ["internal_telemetry"],
                    "suggested_data_sources": available_data_sources if available_data_sources else ["splunk"],
                    "initial_query_templates": {
                        "splunk": "index=* EventCode=10 TargetImage=*lsass.exe"
                    }
                }
            ]
