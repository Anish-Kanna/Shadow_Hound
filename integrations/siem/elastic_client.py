import httpx
import structlog
from typing import Dict, Any, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class ElasticClient:
    """
    Elasticsearch / Elastic SIEM integration.
    Supports EQL (Event Query Language) and Lucene queries.
    """

    def __init__(self, base_url: str = "http://localhost:9200", api_key: Optional[str] = None):
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=60.0)
        self._index = ".siem-signals-*,logs-*,metrics-*"

    def search(self, query: str, index: Optional[str] = None) -> Dict[str, Any]:
        """
        Execute an EQL or Lucene query.
        If query contains 'sequence' or starts with known EQL keywords → use EQL endpoint.
        Otherwise use standard _search.
        """
        target_index = index or self._index
        log.info("elastic_search_start", preview=query[:100])

        is_eql = any(query.strip().startswith(kw) for kw in
                     ["sequence", "sample", "any where", "process where", "network where",
                      "file where", "registry where", "authentication where"])

        if is_eql:
            return self._eql_search(query, target_index)
        return self._lucene_search(query, target_index)

    def _eql_search(self, eql: str, index: str) -> Dict[str, Any]:
        resp = self._client.post(
            f"/{index}/_eql/search",
            json={
                "query": eql,
                "size": 1000,
                "filter": {"range": {"@timestamp": {"gte": "now-7d"}}},
            },
        )
        resp.raise_for_status()
        data = resp.json()

        hits = data.get("hits", {})
        events = hits.get("events", [])
        sequences = hits.get("sequences", [])

        rows = []
        for ev in events:
            row = ev.get("_source", {})
            row["_index"] = ev.get("_index")
            rows.append(row)
        for seq in sequences:
            for ev in seq.get("events", []):
                row = ev.get("_source", {})
                row["_sequence_key"] = seq.get("join_keys")
                rows.append(row)

        columns = list(rows[0].keys()) if rows else []
        log.info("elastic_eql_done", rows=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "elastic"}

    def _lucene_search(self, query: str, index: str) -> Dict[str, Any]:
        resp = self._client.post(
            f"/{index}/_search",
            json={
                "query": {
                    "bool": {
                        "must": [
                            {"query_string": {"query": query}},
                            {"range": {"@timestamp": {"gte": "now-7d"}}},
                        ]
                    }
                },
                "size": 1000,
                "sort": [{"@timestamp": {"order": "desc"}}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        hits = data.get("hits", {}).get("hits", [])
        rows = [h.get("_source", {}) for h in hits]
        columns = list(rows[0].keys()) if rows else []
        log.info("elastic_lucene_done", rows=len(rows))
        return {"rows": rows, "columns": columns, "total": len(rows), "source": "elastic"}

    def get_alerts(self, severity: Optional[str] = None) -> Dict[str, Any]:
        """Fetch SIEM alerts from Elastic Security."""
        q = "signal.status:open"
        if severity:
            q += f" AND signal.rule.severity:{severity}"
        return self._lucene_search(q, ".siem-signals-*")

    def __del__(self):
        self._client.close()
