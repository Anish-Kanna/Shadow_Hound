import json
import re
import structlog
from typing import List, Dict, Any, Optional
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

QUERY_SYSTEM_PROMPT = """You are a senior security engineer expert in writing queries for enterprise security platforms.
You write precise, efficient, safe queries that retrieve targeted evidence for threat hunting.

Platform query languages:
- CrowdStrike Falcon: Event Search using Falcon Query Language (FQL) or GraphQL
- SentinelOne: Deep Visibility query syntax
- Microsoft Defender/Sentinel: Kusto Query Language (KQL)
- Splunk: Search Processing Language (SPL)
- Elastic: EQL (Event Query Language) or Lucene
- MISP: REST API indicator lookups
- VirusTotal: REST API hash/IP/domain lookups
- OpenCTI: GraphQL

Rules:
1. Every query must be bounded by time range (default last 7 days unless hypothesis specifies otherwise)
2. Never write queries that would modify data — SELECT/GET only
3. Limit result sets to 1000 rows maximum unless justified
4. Use specific field names — no wildcard SELECT *
5. Include comments explaining what each query component looks for
6. Flag any query that could be expensive (full table scan) with a warning

Always respond with valid JSON only. No markdown, no prose.
"""

ALLOWED_KQL_OPERATORS = {
    "where", "project", "summarize", "extend", "join", "union", "limit",
    "order by", "sort by", "count", "let", "parse", "extract", "between",
    "ago", "startofday", "endofday", "bin", "distinct", "mv-expand", "render"
}

BLOCKED_PATTERNS = [
    r"\bdrop\b", r"\bdelete\b", r"\btruncate\b", r"\binsert\b",
    r"\bupdate\b", r"\balter\b", r"\bexec\b",
    r"\bexecute\b", r"\bsp_\w+\b", r"\bxp_\w+\b",
]


def validate_query(query_text: str, query_language: str) -> tuple[bool, Optional[str]]:
    """
    Validate a query for safety before presenting for approval.
    Returns (is_safe, violation_reason).
    """
    query_lower = query_text.lower()

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, query_lower):
            return False, f"Query contains blocked pattern: {pattern}"

    if query_language == "KQL":
        if "| invoke" in query_lower:
            return False, "KQL invoke operator is not permitted"

    if query_language == "SPL":
        blocked_spl = [r"\|\s*outputlookup", r"\|\s*collect", r"\|\s*sendemail", r"\|\s*script", r"\|\s*run"]
        for pattern in blocked_spl:
            if re.search(pattern, query_lower):
                return False, f"SPL command not permitted: {pattern}"

    return True, None


def plan_queries(
    hypothesis: Dict[str, Any],
    available_data_sources: List[str],
    evidence_gaps: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Generate platform-specific queries for a hypothesis.
    Returns a list of query plan objects.
    """
    log.info("planning_queries", hypothesis_rank=hypothesis.get("priority_rank"),
             sources=available_data_sources)

    gaps_block = json.dumps(evidence_gaps, indent=2) if evidence_gaps else "None identified yet"

    user_prompt = f"""Generate precise, targeted queries for the following threat hunting hypothesis.

HYPOTHESIS:
{json.dumps(hypothesis, indent=2)}

AVAILABLE DATA SOURCES: {", ".join(available_data_sources)}

EVIDENCE GAPS TO ADDRESS:
{gaps_block}

For each data source that is relevant to this hypothesis, generate 1-3 queries.
Each query must be:
1. Specific to the threat behavior described in the hypothesis
2. Written in the correct query language for that platform
3. Time-bounded to the last 7 days
4. Limited to 1000 results maximum
5. Accompanied by a clear rationale

Return ONLY valid JSON in this exact format:
{{
  "queries": [
    {{
      "data_source": "<source name from: crowdstrike|sentinelone|defender|splunk|sentinel|elastic|misp|virustotal|opencti>",
      "query_language": "<KQL|SPL|FQL|EQL|GraphQL|REST>",
      "query_text": "<complete ready-to-execute query>",
      "query_rationale": "<1-2 sentences explaining what this query looks for and why>",
      "estimated_cost": "<low|medium|high>",
      "expected_field_results": ["field1", "field2"]
    }}
  ]
}}

Only generate queries for data sources that are in the AVAILABLE DATA SOURCES list.
"""

    try:
        response = _get_client().models.generate_content(
            model=settings.llm_model,
            contents=user_prompt,
            config=genai_types.GenerateContentConfig(
                system_instruction=QUERY_SYSTEM_PROMPT,
                max_output_tokens=1024,
                temperature=settings.llm_temperature,
            ),
        )

        raw_text = response.text.strip()

        from agent.json_repair import parse_llm_json
        data = parse_llm_json(raw_text, context="query_plan")
        queries = data.get("queries", [])
    except Exception as e:
        import traceback
        print("!!! GEMINI API ERROR IN QUERY PLANNER:", e)
        traceback.print_exc()
        log.warning("query_planner_fallback_triggered", error=str(e))
        
        hyp_desc = hypothesis.get("description", "").lower() if hypothesis else ""
        
        if "wmi" in hyp_desc or "wmic" in hyp_desc:
            queries = [
                {
                    "data_source": "splunk",
                    "query_language": "SPL",
                    "query_text": "index=* EventCode=4688 Image=*wmic.exe CommandLine=*node* | table _time, host, user, ParentImage, CommandLine | head 1000",
                    "query_rationale": "Audit wmic.exe process creation logs targeting remote nodes to trace lateral movement attempts.",
                    "estimated_cost": "low",
                    "expected_field_results": ["_time", "host", "user", "CommandLine"]
                },
                {
                    "data_source": "sentinel",
                    "query_language": "KQL",
                    "query_text": "SecurityEvent | where EventID == 4688 | where NewProcessName has 'wmic.exe' and CommandLine has 'node' | project TimeGenerated, Computer, Account, NewProcessName, CommandLine | take 1000",
                    "query_rationale": "Query Sentinel for Security Event 4688 events indicating remote execution via WMIC command line.",
                    "estimated_cost": "medium",
                    "expected_field_results": ["TimeGenerated", "Computer", "Account", "CommandLine"]
                }
            ]
        elif "network" in hyp_desc or "beacon" in hyp_desc or "c2" in hyp_desc:
            queries = [
                {
                    "data_source": "splunk",
                    "query_language": "SPL",
                    "query_text": "index=network dest_port=443 | stats count, dc(dest_ip) by src_ip | sort - count | head 100",
                    "query_rationale": "Analyze firewall logs for outbound HTTP connection beacons to anomalous IP addresses.",
                    "estimated_cost": "medium",
                    "expected_field_results": ["src_ip", "count", "dc(dest_ip)"]
                },
                {
                    "data_source": "sentinel",
                    "query_language": "KQL",
                    "query_text": "CommonSecurityLog | where DeviceAction == 'Accept' and DestinationPort == 443 | summarize Count = count() by SourceIP, DestinationIP | sort by Count desc | take 100",
                    "query_rationale": "Query Sentinel firewall telemetry to isolate host IP addresses generating high volume TLS connections.",
                    "estimated_cost": "medium",
                    "expected_field_results": ["SourceIP", "DestinationIP", "Count"]
                }
            ]
        else:
            queries = [
                {
                    "data_source": "splunk",
                    "query_language": "SPL",
                    "query_text": "index=* EventCode=4688 CommandLine=*EncodedCommand* | table _time, host, user, ProcessName, CommandLine | head 1000",
                    "query_rationale": "Identify encoded PowerShell commands executed across domain endpoints to detect obfuscated execution.",
                    "estimated_cost": "medium",
                    "expected_field_results": ["_time", "host", "user", "CommandLine"]
                },
                {
                    "data_source": "sentinel",
                    "query_language": "KQL",
                    "query_text": "SecurityEvent | where EventID == 4688 | where CommandLine contains 'EncodedCommand' or CommandLine contains 'lsass' | project TimeGenerated, Computer, Account, NewProcessName, CommandLine | take 1000",
                    "query_rationale": "Query Microsoft Sentinel for process creation events matching suspicious encoded parameters or LSASS target.",
                    "estimated_cost": "medium",
                    "expected_field_results": ["TimeGenerated", "Computer", "Account", "CommandLine"]
                }
            ]

    # Validate every query for safety
    validated_queries = []
    for q in queries:
        is_safe, violation = validate_query(q["query_text"], q.get("query_language", ""))
        q["validation_passed"] = is_safe
        q["validation_violation"] = violation
        if not is_safe:
            log.warning("query_failed_validation",
                        source=q["data_source"],
                        violation=violation)
        validated_queries.append(q)

    log.info("queries_planned", count=len(validated_queries))
    return validated_queries
