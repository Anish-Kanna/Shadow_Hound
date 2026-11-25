import time
import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class SplunkClient:
    """
    Splunk Enterprise / Splunk Cloud integration via REST API.
    Uses token-based auth (Bearer) or username/password.
    Supports SPL search jobs with full async polling.
    """

    def __init__(self):
        base = f"https://{settings.splunk_host}:{settings.splunk_port}"
        self._client = httpx.Client(
            base_url=base,
            headers={"Authorization": f"Bearer {settings.splunk_token}"},
            verify=False,   # Many on-prem Splunk installs use self-signed certs
            timeout=120.0,
        )

    def run_search(self, spl_query: str, earliest: str = "-7d", latest: str = "now") -> Dict[str, Any]:
        """
        Submit a SPL search job and poll until complete, then return results.
        """
        log.info("splunk_search_start", spl_preview=spl_query[:120])

        # Ensure query starts with 'search' command
        if not spl_query.strip().lower().startswith("search"):
            spl_query = f"search {spl_query}"

        # Submit job
        create_resp = self._client.post(
            "/services/search/jobs",
            data={
                "search": spl_query,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
                "max_count": 1000,
            },
        )
        create_resp.raise_for_status()
        sid = create_resp.json()["sid"]
        log.info("splunk_job_created", sid=sid)

        # Poll until done
        max_polls = 120
        for _ in range(max_polls):
            status_resp = self._client.get(
                f"/services/search/jobs/{sid}",
                params={"output_mode": "json"},
            )
            status_resp.raise_for_status()
            content = status_resp.json()["entry"][0]["content"]
            dispatch_state = content["dispatchState"]

            if dispatch_state in ("DONE", "FAILED"):
                break
            time.sleep(2)

        if dispatch_state != "DONE":
            log.warning("splunk_search_incomplete", state=dispatch_state, sid=sid)
            return {"rows": [], "columns": [], "total": 0, "source": "splunk", "state": dispatch_state}

        # Fetch results
        results_resp = self._client.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 1000},
        )
        results_resp.raise_for_status()
        data = results_resp.json()
        rows = data.get("results", [])
        # Strip Splunk internal fields (prefixed with _)
        cleaned_rows = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows]
        columns = list(cleaned_rows[0].keys()) if cleaned_rows else []

        log.info("splunk_search_done", rows=len(cleaned_rows))
        return {"rows": cleaned_rows, "columns": columns, "total": len(cleaned_rows), "source": "splunk"}

    def get_notable_events(self, hours_back: int = 24, severity: Optional[str] = None) -> Dict[str, Any]:
        """Fetch ES notable events."""
        spl = f'search index=notable earliest=-{hours_back}h'
        if severity:
            spl += f' urgency={severity}'
        spl += ' | table _time, rule_name, urgency, src, dest, user | sort -_time'
        return self.run_search(spl)

    def get_authentication_events(self, username: Optional[str] = None, src_ip: Optional[str] = None) -> Dict[str, Any]:
        """Query authentication logs."""
        spl = 'search index=* sourcetype=WinEventLog:Security (EventCode=4624 OR EventCode=4625 OR EventCode=4648)'
        if username:
            spl += f' Account_Name={username}'
        if src_ip:
            spl += f' Source_Network_Address={src_ip}'
        spl += ' | table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type, Workstation_Name | sort -_time'
        return self.run_search(spl)

    def get_process_events(self, process_name: Optional[str] = None, parent_process: Optional[str] = None) -> Dict[str, Any]:
        """Query process creation events (Sysmon Event ID 1)."""
        spl = 'search index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1'
        if process_name:
            spl += f' Image="*{process_name}*"'
        if parent_process:
            spl += f' ParentImage="*{parent_process}*"'
        spl += ' | table _time, Image, CommandLine, ParentImage, ParentCommandLine, User, Computer | sort -_time'
        return self.run_search(spl)

    def get_network_connections(self, dest_ip: Optional[str] = None, dest_port: Optional[int] = None) -> Dict[str, Any]:
        """Query network connection events (Sysmon Event ID 3)."""
        spl = 'search index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3'
        if dest_ip:
            spl += f' DestinationIp={dest_ip}'
        if dest_port:
            spl += f' DestinationPort={dest_port}'
        spl += ' | table _time, Image, SourceIp, SourcePort, DestinationIp, DestinationPort, User | sort -_time'
        return self.run_search(spl)

    def __del__(self):
        self._client.close()
