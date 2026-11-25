import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class SentinelOneClient:
    """
    SentinelOne Deep Visibility integration.
    Uses token-based auth with pagination support.
    """

    def __init__(self):
        self._client = httpx.Client(
            base_url=settings.sentinelone_base_url or "",
            headers={
                "Authorization": f"ApiToken {settings.sentinelone_api_token}",
                "Content-Type": "application/json",
            },
            timeout=120.0,
        )

    def execute_deep_visibility(self, query: str, days_back: int = 7) -> Dict[str, Any]:
        """
        Create and poll a Deep Visibility query.
        SentinelOne DV is async — create query, poll until complete, fetch results.
        """
        from_date = (datetime.now(timezone.utc) - timedelta(days=days_back)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        to_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        log.info("sentinelone_dv_query_start", query_preview=query[:100])

        # Step 1: Create query
        create_resp = self._client.post(
            "/web/api/v2.1/dv/init-query",
            json={
                "query": query,
                "fromDate": from_date,
                "toDate": to_date,
                "limit": 1000,
            },
        )
        create_resp.raise_for_status()
        query_id = create_resp.json()["data"]["queryId"]

        # Step 2: Poll for completion
        import time
        max_polls = 60
        for _ in range(max_polls):
            status_resp = self._client.get(f"/web/api/v2.1/dv/query-status?queryId={query_id}")
            status_resp.raise_for_status()
            status = status_resp.json()["data"]["responseState"]

            if status in ("FINISHED", "FAILED", "TIMEOUT"):
                break
            time.sleep(3)

        if status != "FINISHED":
            log.warning("sentinelone_dv_query_incomplete", status=status, query_id=query_id)
            return {"rows": [], "columns": [], "total": 0, "source": "sentinelone", "status": status}

        # Step 3: Fetch results
        events_resp = self._client.get(
            f"/web/api/v2.1/dv/events?queryId={query_id}&limit=1000"
        )
        events_resp.raise_for_status()
        data = events_resp.json()["data"]
        rows = data if isinstance(data, list) else []
        columns = list(rows[0].keys()) if rows else []

        log.info("sentinelone_dv_done", rows=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "sentinelone"}

    def get_threats(self, resolved: bool = False, limit: int = 1000) -> Dict[str, Any]:
        """Get threat detections from SentinelOne."""
        resp = self._client.get(
            "/web/api/v2.1/threats",
            params={
                "resolved": str(resolved).lower(),
                "limit": limit,
                "sortBy": "createdAt",
                "sortOrder": "desc",
            },
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return {"rows": data, "columns": list(data[0].keys()) if data else [], "total": len(data)}

    def get_processes(self, agent_id: str) -> Dict[str, Any]:
        """Get running processes on an agent."""
        resp = self._client.get(
            "/web/api/v2.1/agents/processes",
            params={"ids": agent_id},
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        return {"rows": data, "columns": list(data[0].keys()) if data else [], "total": len(data)}

    def __del__(self):
        self._client.close()
