import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class DefenderClient:
    """
    Microsoft Defender for Endpoint + Microsoft Sentinel integration.
    Uses Microsoft Graph API / Security API with MSAL OAuth2 auth.
    Supports KQL queries via the Advanced Hunting endpoint.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    SECURITY_BASE = "https://api.securitycenter.microsoft.com/api"
    TOKEN_URL = (
        f"https://login.microsoftonline.com/{settings.defender_tenant_id}/oauth2/v2.0/token"
    )

    SCOPES = [
        "https://api.securitycenter.microsoft.com/.default",
        "https://graph.microsoft.com/.default",
    ]

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
                "scope": "https://api.securitycenter.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expires_at = now + timedelta(seconds=data.get("expires_in", 3600) - 60)
        log.info("defender_token_refreshed")
        return self._token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def advanced_hunting(self, kql_query: str) -> Dict[str, Any]:
        """
        Run a KQL query via Microsoft Defender Advanced Hunting API.
        Returns normalized result dict.
        """
        log.info("defender_advanced_hunting_start")

        resp = self._client.post(
            f"{self.SECURITY_BASE}/advancedqueries/run",
            headers=self._headers(),
            json={"Query": kql_query},
        )
        resp.raise_for_status()
        data = resp.json()

        schema = data.get("Schema", [])
        results = data.get("Results", [])
        columns = [col["Name"] for col in schema]

        log.info("defender_hunting_done", rows=len(results))
        return {
            "rows": results,
            "columns": columns,
            "total": len(results),
            "source": "defender",
        }

    def get_machine_timeline(self, machine_id: str, hours: int = 48) -> Dict[str, Any]:
        """Retrieve timeline events for a specific machine."""
        resp = self._client.get(
            f"{self.SECURITY_BASE}/machines/{machine_id}/events",
            headers=self._headers(),
            params={"$top": 1000},
        )
        resp.raise_for_status()
        data = resp.json()
        events = data.get("value", [])
        return {"rows": events, "columns": list(events[0].keys()) if events else [], "total": len(events)}

    def get_alerts(self, severity: Optional[str] = None, hours: int = 168) -> Dict[str, Any]:
        """Get security alerts, optionally filtered by severity."""
        from urllib.parse import urlencode
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        params = {"$filter": f"alertCreationTime ge {since}", "$top": 1000}
        if severity:
            params["$filter"] += f" and severity eq '{severity}'"

        resp = self._client.get(
            f"{self.SECURITY_BASE}/alerts",
            headers=self._headers(),
            params=params,
        )
        resp.raise_for_status()
        data = resp.json()
        alerts = data.get("value", [])
        return {"rows": alerts, "columns": list(alerts[0].keys()) if alerts else [], "total": len(alerts)}

    def get_indicators(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """Check if an IOC is in Defender's indicator database."""
        resp = self._client.get(
            f"{self.SECURITY_BASE}/indicators",
            headers=self._headers(),
            params={"$filter": f"indicatorValue eq '{ioc_value}' and indicatorType eq '{ioc_type}'"},
        )
        resp.raise_for_status()
        data = resp.json()
        return {"rows": data.get("value", []), "total": len(data.get("value", []))}

    def __del__(self):
        self._client.close()
