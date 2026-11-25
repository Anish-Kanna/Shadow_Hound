import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class SentinelClient:
    """
    Microsoft Sentinel (Azure Monitor / Log Analytics) integration.
    Uses the Log Analytics Query API with OAuth2 client credentials.
    Runs KQL queries against the workspace.
    """

    TOKEN_URL = f"https://login.microsoftonline.com/{settings.defender_tenant_id}/oauth2/v2.0/token"
    QUERY_URL = (
        f"https://api.loganalytics.io/v1/workspaces/{settings.sentinel_workspace_id}/query"
    )

    def __init__(self):
        self._token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._client = httpx.Client(timeout=120.0)

    def _get_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._token and self._token_expires_at and now < self._token_expires_at:
            return self._token

        resp = self._client.post(
            self.TOKEN_URL,
            data={
                "client_id": settings.defender_client_id,
                "client_secret": settings.defender_client_secret,
                "scope": "https://api.loganalytics.io/.default",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expires_at = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
        log.info("sentinel_token_refreshed")
        return self._token

    def run_query(self, kql_query: str, timespan: str = "P7D") -> Dict[str, Any]:
        """
        Execute a KQL query against Microsoft Sentinel workspace.
        timespan: ISO 8601 duration e.g. P7D = last 7 days, PT1H = last hour
        """
        log.info("sentinel_query_start", preview=kql_query[:120])

        resp = self._client.post(
            self.QUERY_URL,
            headers={
                "Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json",
            },
            json={"query": kql_query, "timespan": timespan},
        )
        resp.raise_for_status()
        data = resp.json()

        tables = data.get("tables", [])
        if not tables:
            return {"rows": [], "columns": [], "total": 0, "source": "sentinel"}

        table = tables[0]
        columns = [col["name"] for col in table.get("columns", [])]
        raw_rows = table.get("rows", [])
        rows = [dict(zip(columns, row)) for row in raw_rows]

        log.info("sentinel_query_done", rows=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "sentinel"}

    def get_security_alerts(self, hours: int = 48) -> Dict[str, Any]:
        kql = f"""SecurityAlert
| where TimeGenerated >= ago({hours}h)
| project TimeGenerated, AlertName, AlertSeverity, Description, Entities, Tactics
| sort by TimeGenerated desc
| limit 1000"""
        return self.run_query(kql)

    def get_signin_anomalies(self, user: Optional[str] = None) -> Dict[str, Any]:
        user_filter = f'| where UserPrincipalName == "{user}"' if user else ""
        kql = f"""SigninLogs
{user_filter}
| where TimeGenerated >= ago(7d)
| where RiskLevelDuringSignIn in ("high", "medium")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, RiskLevelDuringSignIn, Status
| sort by TimeGenerated desc
| limit 1000"""
        return self.run_query(kql)

    def get_rare_process_executions(self) -> Dict[str, Any]:
        kql = """DeviceProcessEvents
| where Timestamp >= ago(7d)
| summarize Count=count() by FolderPath, FileName
| where Count < 5
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp >= ago(7d)
    | project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName
) on FolderPath, FileName
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFileName, Count
| sort by Timestamp desc
| limit 1000"""
        return self.run_query(kql)

    def get_lateral_movement_indicators(self) -> Dict[str, Any]:
        kql = """DeviceLogonEvents
| where Timestamp >= ago(7d)
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| summarize
    LogonCount=count(),
    Targets=make_set(DeviceName),
    FirstSeen=min(Timestamp),
    LastSeen=max(Timestamp)
    by AccountName, RemoteIP
| where array_length(Targets) > 3
| sort by LogonCount desc
| limit 1000"""
        return self.run_query(kql)

    def __del__(self):
        self._client.close()
