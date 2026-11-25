import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
from functools import lru_cache
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class CrowdStrikeClient:
    """
    CrowdStrike Falcon integration using OAuth2 + Event Search API.
    Supports FQL (Falcon Query Language) for Event Search.
    """

    BASE_URL = settings.crowdstrike_base_url
    TOKEN_URL = f"{settings.crowdstrike_base_url}/oauth2/token"

    def __init__(self):
        self._token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        self._client = httpx.Client(timeout=60.0)

    def _get_token(self) -> str:
        now = datetime.now(timezone.utc)
        if self._token and self._token_expires_at and now < self._token_expires_at:
            return self._token

        resp = self._client.post(
            self.TOKEN_URL,
            data={
                "client_id": settings.crowdstrike_client_id,
                "client_secret": settings.crowdstrike_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        self._token_expires_at = now + timedelta(seconds=data.get("expires_in", 1800) - 60)
        log.info("crowdstrike_token_refreshed")
        return self._token

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def execute_query(self, query_text: str, language: str = "FQL") -> Dict[str, Any]:
        """
        Execute a Falcon Event Search query.
        Returns normalized result dict with 'rows', 'columns', 'total'.
        """
        log.info("crowdstrike_query_start", language=language)

        # Falcon Event Search uses a two-step: search IDs then fetch details
        search_resp = self._client.get(
            f"{self.BASE_URL}/incidents/queries/incidents/v1",
            headers=self._headers(),
            params={
                "filter": query_text,
                "limit": 1000,
            },
        )
        search_resp.raise_for_status()
        ids = search_resp.json().get("resources", [])

        if not ids:
            return {"rows": [], "columns": [], "total": 0, "source": "crowdstrike"}

        # Fetch full event details
        detail_resp = self._client.post(
            f"{self.BASE_URL}/incidents/entities/incidents/GET/v1",
            headers=self._headers(),
            json={"ids": ids[:100]},  # Batch limit
        )
        detail_resp.raise_for_status()
        resources = detail_resp.json().get("resources", [])

        rows = [self._normalize_event(r) for r in resources]
        columns = list(rows[0].keys()) if rows else []

        log.info("crowdstrike_query_done", rows=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "crowdstrike"}

    def get_process_tree(self, device_id: str, process_id: str) -> Dict[str, Any]:
        """Retrieve the full process execution tree for a given process."""
        resp = self._client.get(
            f"{self.BASE_URL}/processes/entities/processes/v1",
            headers=self._headers(),
            params={"ids": [f"{device_id}:{process_id}"]},
        )
        resp.raise_for_status()
        return resp.json()

    def get_network_connections(self, device_id: str, start_time: str) -> Dict[str, Any]:
        """Get network connections for a device since start_time."""
        fql_filter = f"device_id:'{device_id}'+timestamp:>='{start_time}'"
        return self.execute_query(fql_filter)

    @staticmethod
    def _normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "incident_id": raw.get("incident_id"),
            "created_at": raw.get("created"),
            "updated_at": raw.get("modified_timestamp"),
            "status": raw.get("status"),
            "severity": raw.get("severity"),
            "tactics": raw.get("tactics", []),
            "techniques": raw.get("techniques", []),
            "hosts": raw.get("hosts", []),
            "users": raw.get("users", []),
            "description": raw.get("description"),
            "raw": raw,
        }

    def __del__(self):
        self._client.close()
