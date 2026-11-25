import httpx
import structlog
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class MISPClient:
    """
    MISP (Malware Information Sharing Platform) integration.
    Uses MISP REST API with API key auth.
    Fetches events, attributes, and indicators.
    """

    def __init__(self):
        self._client = httpx.Client(
            base_url=settings.misp_url or "",
            headers={
                "Authorization": settings.misp_api_key or "",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            verify=False,
            timeout=60.0,
        )

    def get_recent_events(self, days: int = 7, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch recent MISP events for hypothesis context."""
        from_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")

        resp = self._client.post(
            "/events/restSearch",
            json={
                "returnFormat": "json",
                "dateFrom": from_date,
                "limit": limit,
                "includeEventTags": True,
                "includeGalaxy": False,
                "metadata": True,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        events = data.get("response", [])

        normalized = []
        for ev_wrapper in events:
            ev = ev_wrapper.get("Event", ev_wrapper)
            normalized.append({
                "id": ev.get("id"),
                "uuid": ev.get("uuid"),
                "info": ev.get("info"),
                "date": ev.get("date"),
                "threat_level": ev.get("threat_level_id"),
                "tags": [t.get("name") for t in ev.get("Tag", [])],
                "attribute_count": ev.get("attribute_count"),
                "source": "misp",
            })

        log.info("misp_events_fetched", count=len(normalized))
        return normalized

    def search_indicators(self, query: str) -> Dict[str, Any]:
        """
        Search MISP attributes by value or type.
        query can be: an IP, domain, hash, or free-text event description.
        """
        log.info("misp_search_start", query=query[:100])

        resp = self._client.post(
            "/attributes/restSearch",
            json={
                "returnFormat": "json",
                "value": query,
                "limit": 500,
                "includeEventTags": True,
                "enforceWarninglist": True,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        attributes = data.get("response", {}).get("Attribute", [])

        rows = []
        for attr in attributes:
            rows.append({
                "attribute_id": attr.get("id"),
                "event_id": attr.get("event_id"),
                "type": attr.get("type"),
                "value": attr.get("value"),
                "category": attr.get("category"),
                "timestamp": attr.get("timestamp"),
                "comment": attr.get("comment"),
                "to_ids": attr.get("to_ids"),
                "tags": [t.get("name") for t in attr.get("Tag", [])],
            })

        columns = list(rows[0].keys()) if rows else []
        log.info("misp_search_done", hits=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "misp"}

    def get_event_details(self, event_id: str) -> Dict[str, Any]:
        """Fetch full event details including all attributes."""
        resp = self._client.get(f"/events/{event_id}")
        resp.raise_for_status()
        ev = resp.json().get("Event", {})
        return {
            "id": ev.get("id"),
            "info": ev.get("info"),
            "date": ev.get("date"),
            "attributes": ev.get("Attribute", []),
            "objects": ev.get("Object", []),
            "galaxies": ev.get("Galaxy", []),
            "tags": [t.get("name") for t in ev.get("Tag", [])],
        }

    def get_ioc_by_type(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Look up a specific IOC by type (ip-dst, domain, md5, sha256, url, etc)."""
        resp = self._client.post(
            "/attributes/restSearch",
            json={
                "returnFormat": "json",
                "type": ioc_type,
                "value": value,
                "enforceWarninglist": True,
            },
        )
        resp.raise_for_status()
        attrs = resp.json().get("response", {}).get("Attribute", [])
        return {
            "found": len(attrs) > 0,
            "results": attrs,
            "source": "misp",
            "ioc_type": ioc_type,
            "value": value,
        }

    def __del__(self):
        self._client.close()
