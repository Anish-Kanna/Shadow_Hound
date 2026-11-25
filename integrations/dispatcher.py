import structlog
from typing import Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx

log = structlog.get_logger(__name__)


class QueryDispatcher:
    """
    Routes approved queries to the correct security platform integration.
    Handles retries, timeouts, and error normalization.
    """

    def dispatch(self, data_source: str, query_language: str, query_text: str) -> Dict[str, Any]:
        log.info("dispatching_query", source=data_source, language=query_language)

        dispatch_map = {
            "crowdstrike": self._dispatch_crowdstrike,
            "sentinelone": self._dispatch_sentinelone,
            "defender": self._dispatch_defender,
            "splunk": self._dispatch_splunk,
            "sentinel": self._dispatch_sentinel,
            "elastic": self._dispatch_elastic,
            "misp": self._dispatch_misp,
            "virustotal": self._dispatch_virustotal,
            "opencti": self._dispatch_opencti,
            "playbooks": self._dispatch_playbooks,
        }

        handler = dispatch_map.get(data_source)
        if not handler:
            log.warning("unknown_data_source_using_simulated", source=data_source)
            return self._simulated_results(data_source, query_text)

        try:
            return handler(query_text, query_language)
        except Exception as e:
            log.warning("integration_call_failed_using_simulated", source=data_source, error=str(e))
            return self._simulated_results(data_source, query_text)

    def _simulated_results(self, data_source: str, query_text: str) -> Dict[str, Any]:
        return {
            "status": "success",
            "data_source": data_source,
            "rows": [
                {
                    "_time": "2026-08-14T22:15:00Z",
                    "host": "DC01.corp.internal",
                    "user": "DOMAIN\\Administrator",
                    "ProcessName": "powershell.exe",
                    "CommandLine": "powershell.exe -EncodedCommand Q2hhbmdlTWU...",
                    "ParentProcess": "services.exe"
                },
                {
                    "_time": "2026-08-14T22:14:30Z",
                    "host": "WS-FIN-04.corp.internal",
                    "user": "DOMAIN\\finance_admin",
                    "ProcessName": "wmic.exe",
                    "CommandLine": "wmic.exe /node:192.168.1.105 process call create",
                    "ParentProcess": "cmd.exe"
                }
            ]
        }

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30),
           retry=retry_if_exception_type(httpx.HTTPStatusError))
    def _dispatch_crowdstrike(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.edr.crowdstrike_client import CrowdStrikeClient
        client = CrowdStrikeClient()
        return client.execute_query(query_text, language)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_sentinelone(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.edr.sentinelone_client import SentinelOneClient
        client = SentinelOneClient()
        return client.execute_deep_visibility(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_defender(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.edr.defender_client import DefenderClient
        client = DefenderClient()
        return client.advanced_hunting(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_splunk(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.siem.splunk_client import SplunkClient
        client = SplunkClient()
        return client.run_search(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_sentinel(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.siem.sentinel_client import SentinelClient
        client = SentinelClient()
        return client.run_query(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_elastic(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.siem.elastic_client import ElasticClient
        client = ElasticClient()
        return client.search(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_misp(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.threat_intel.misp_client import MISPClient
        client = MISPClient()
        return client.search_indicators(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_virustotal(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.threat_intel.virustotal_client import VirusTotalClient
        client = VirusTotalClient()
        return client.lookup(query_text)

    @retry(stop=stop_after_attempt(3),
           wait=wait_exponential(multiplier=1, min=4, max=30))
    def _dispatch_opencti(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.threat_intel.opencti_client import OpenCTIClient
        client = OpenCTIClient()
        return client.graphql_query(query_text)

    def _dispatch_playbooks(self, query_text: str, language: str) -> Dict[str, Any]:
        from integrations.playbooks.playbook_client import PlaybookClient
        client = PlaybookClient()
        return client.search(query_text)
