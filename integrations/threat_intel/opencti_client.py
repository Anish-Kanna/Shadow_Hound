import httpx
import structlog
from typing import Dict, Any, List, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class OpenCTIClient:
    """
    OpenCTI GraphQL API integration.
    Supports indicator lookups, threat actor profiles, and campaign data.
    """

    def __init__(self):
        self._client = httpx.Client(
            base_url=settings.opencti_url or "",
            headers={
                "Authorization": f"Bearer {settings.opencti_token or ''}",
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

    def graphql_query(self, query: str) -> Dict[str, Any]:
        """Execute a raw GraphQL query against OpenCTI."""
        log.info("opencti_query_start", preview=query[:120])
        resp = self._client.post("/graphql", json={"query": query})
        resp.raise_for_status()
        data = resp.json()
        if "errors" in data:
            log.error("opencti_graphql_error", errors=data["errors"])
            raise ValueError(f"OpenCTI GraphQL error: {data['errors']}")
        return {"rows": [data.get("data", {})], "columns": [], "total": 1, "source": "opencti"}

    def search_indicators(self, value: str) -> Dict[str, Any]:
        """Search for indicators matching a value."""
        query = f"""
        query {{
            stixCyberObservables(filters: {{
                key: value, values: ["{value}"]
            }}) {{
                edges {{
                    node {{
                        id
                        entity_type
                        observable_value
                        created_at
                        indicators {{
                            edges {{ node {{ id name pattern confidence }} }}
                        }}
                        reports {{
                            edges {{ node {{ id name published }} }}
                        }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query)
        raw = result.get("rows", [{}])[0]
        observables = raw.get("stixCyberObservables", {}).get("edges", [])
        rows = [edge["node"] for edge in observables]
        return {"rows": rows, "columns": list(rows[0].keys()) if rows else [], "total": len(rows), "source": "opencti"}

    def get_threat_actors(self, limit: int = 20) -> Dict[str, Any]:
        """Fetch recent threat actor profiles."""
        query = f"""
        query {{
            threatActors(first: {limit}, orderBy: modified, orderMode: desc) {{
                edges {{
                    node {{
                        id name description
                        aliases
                        sophistication
                        resource_level
                        primary_motivation
                        country {{ name }}
                        modified
                        confidence
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query)
        raw = result.get("rows", [{}])[0]
        actors = raw.get("threatActors", {}).get("edges", [])
        rows = [edge["node"] for edge in actors]
        return {"rows": rows, "columns": list(rows[0].keys()) if rows else [], "total": len(rows), "source": "opencti"}

    def get_ttps_for_actor(self, actor_name: str) -> Dict[str, Any]:
        """Get ATT&CK techniques associated with a threat actor."""
        query = f"""
        query {{
            threatActors(filters: {{ key: name, values: ["{actor_name}"] }}) {{
                edges {{
                    node {{
                        id name
                        attackPatterns {{
                            edges {{
                                node {{
                                    id name
                                    x_mitre_id
                                    description
                                    killChainPhases {{ kill_chain_name phase_name }}
                                }}
                            }}
                        }}
                    }}
                }}
            }}
        }}
        """
        result = self.graphql_query(query)
        raw = result.get("rows", [{}])[0]
        actors = raw.get("threatActors", {}).get("edges", [])
        ttps = []
        for actor in actors:
            for ap in actor["node"].get("attackPatterns", {}).get("edges", []):
                ttps.append(ap["node"])
        return {"rows": ttps, "columns": list(ttps[0].keys()) if ttps else [], "total": len(ttps), "source": "opencti"}

    def __del__(self):
        self._client.close()
