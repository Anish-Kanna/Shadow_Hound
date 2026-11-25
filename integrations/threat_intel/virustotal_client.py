import httpx
import structlog
from typing import Dict, Any, Optional
from config.settings import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()


class VirusTotalClient:
    """
    VirusTotal API v3 integration.
    Supports IOC lookups: file hashes, IPs, domains, URLs.
    Applies local caching to avoid re-querying within a hunt session.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self._client = httpx.Client(
            base_url=self.BASE_URL,
            headers={"x-apikey": settings.virustotal_api_key or ""},
            timeout=30.0,
        )
        self._cache: Dict[str, Any] = {}

    def lookup(self, indicator: str) -> Dict[str, Any]:
        """
        Auto-detect indicator type and lookup in VT.
        Supports: IPv4, domain, URL, MD5/SHA1/SHA256 hash.
        """
        if indicator in self._cache:
            return self._cache[indicator]

        ioc_type = self._detect_type(indicator)
        log.info("virustotal_lookup", ioc_type=ioc_type, indicator=indicator[:60])

        if ioc_type == "ip":
            result = self._lookup_ip(indicator)
        elif ioc_type == "domain":
            result = self._lookup_domain(indicator)
        elif ioc_type == "url":
            result = self._lookup_url(indicator)
        elif ioc_type == "file":
            result = self._lookup_hash(indicator)
        else:
            result = {"error": f"Cannot determine IOC type for: {indicator}", "rows": [], "total": 0}

        self._cache[indicator] = result
        return result

    def _lookup_ip(self, ip: str) -> Dict[str, Any]:
        resp = self._client.get(f"/ip_addresses/{ip}")
        if resp.status_code == 404:
            return {"rows": [], "total": 0, "source": "virustotal", "found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        row = {
            "indicator": ip,
            "type": "ip",
            "malicious_votes": last_analysis.get("malicious", 0),
            "suspicious_votes": last_analysis.get("suspicious", 0),
            "harmless_votes": last_analysis.get("harmless", 0),
            "undetected_votes": last_analysis.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "country": attrs.get("country"),
            "as_owner": attrs.get("as_owner"),
            "asn": attrs.get("asn"),
            "network": attrs.get("network"),
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "is_malicious": last_analysis.get("malicious", 0) > 2,
        }
        return {"rows": [row], "columns": list(row.keys()), "total": 1, "source": "virustotal", "found": True}

    def _lookup_domain(self, domain: str) -> Dict[str, Any]:
        resp = self._client.get(f"/domains/{domain}")
        if resp.status_code == 404:
            return {"rows": [], "total": 0, "source": "virustotal", "found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        row = {
            "indicator": domain,
            "type": "domain",
            "malicious_votes": last_analysis.get("malicious", 0),
            "suspicious_votes": last_analysis.get("suspicious", 0),
            "harmless_votes": last_analysis.get("harmless", 0),
            "reputation": attrs.get("reputation", 0),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "categories": attrs.get("categories", {}),
            "tags": attrs.get("tags", []),
            "is_malicious": last_analysis.get("malicious", 0) > 2,
        }
        return {"rows": [row], "columns": list(row.keys()), "total": 1, "source": "virustotal", "found": True}

    def _lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        resp = self._client.get(f"/files/{file_hash}")
        if resp.status_code == 404:
            return {"rows": [], "total": 0, "source": "virustotal", "found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        row = {
            "indicator": file_hash,
            "type": "file",
            "name": attrs.get("meaningful_name") or attrs.get("name"),
            "size": attrs.get("size"),
            "md5": attrs.get("md5"),
            "sha1": attrs.get("sha1"),
            "sha256": attrs.get("sha256"),
            "malicious_votes": last_analysis.get("malicious", 0),
            "suspicious_votes": last_analysis.get("suspicious", 0),
            "harmless_votes": last_analysis.get("harmless", 0),
            "file_type": attrs.get("type_description"),
            "magic": attrs.get("magic"),
            "tags": attrs.get("tags", []),
            "threat_names": list(set(
                v.get("result") for v in attrs.get("last_analysis_results", {}).values()
                if v.get("category") == "malicious" and v.get("result")
            )),
            "is_malicious": last_analysis.get("malicious", 0) > 5,
        }
        return {"rows": [row], "columns": list(row.keys()), "total": 1, "source": "virustotal", "found": True}

    def _lookup_url(self, url: str) -> Dict[str, Any]:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = self._client.get(f"/urls/{url_id}")
        if resp.status_code == 404:
            return {"rows": [], "total": 0, "source": "virustotal", "found": False}
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        last_analysis = attrs.get("last_analysis_stats", {})
        row = {
            "indicator": url,
            "type": "url",
            "malicious_votes": last_analysis.get("malicious", 0),
            "suspicious_votes": last_analysis.get("suspicious", 0),
            "harmless_votes": last_analysis.get("harmless", 0),
            "final_url": attrs.get("last_final_url"),
            "title": attrs.get("title"),
            "tags": attrs.get("tags", []),
            "is_malicious": last_analysis.get("malicious", 0) > 2,
        }
        return {"rows": [row], "columns": list(row.keys()), "total": 1, "source": "virustotal", "found": True}

    @staticmethod
    def _detect_type(indicator: str) -> str:
        import re
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
            return "ip"
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", indicator):
            return "file"
        if indicator.startswith("http://") or indicator.startswith("https://"):
            return "url"
        if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", indicator):
            return "domain"
        return "unknown"

    def __del__(self):
        self._client.close()
