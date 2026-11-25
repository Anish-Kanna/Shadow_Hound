import os
import yaml
import json
import structlog
from pathlib import Path
from typing import Dict, Any, List, Optional

log = structlog.get_logger(__name__)

PLAYBOOKS_DIR = Path(__file__).parent.parent.parent / "data" / "playbooks"


class PlaybookClient:
    """
    Loads and searches internal hunt playbooks and SIGMA rules.
    Playbooks are YAML files stored in data/playbooks/.
    """

    def __init__(self):
        self._playbooks: Optional[List[Dict[str, Any]]] = None

    def _load_playbooks(self) -> List[Dict[str, Any]]:
        if self._playbooks is not None:
            return self._playbooks

        playbooks = []
        if not PLAYBOOKS_DIR.exists():
            log.warning("playbooks_dir_missing", path=str(PLAYBOOKS_DIR))
            return playbooks

        for fpath in PLAYBOOKS_DIR.glob("**/*.yml"):
            try:
                with open(fpath) as f:
                    data = yaml.safe_load(f)
                    if data:
                        data["_file"] = str(fpath.relative_to(PLAYBOOKS_DIR))
                        playbooks.append(data)
            except Exception as e:
                log.warning("playbook_load_error", file=str(fpath), error=str(e))

        for fpath in PLAYBOOKS_DIR.glob("**/*.json"):
            try:
                with open(fpath) as f:
                    data = json.load(f)
                    if data:
                        data["_file"] = str(fpath.relative_to(PLAYBOOKS_DIR))
                        playbooks.append(data)
            except Exception as e:
                log.warning("playbook_load_error", file=str(fpath), error=str(e))

        self._playbooks = playbooks
        log.info("playbooks_loaded", count=len(playbooks))
        return playbooks

    def search(self, query: str) -> Dict[str, Any]:
        """
        Semantic keyword search across playbooks.
        Searches title, description, tags, mitre_attack fields.
        """
        playbooks = self._load_playbooks()
        query_lower = query.lower()
        tokens = set(query_lower.split())

        scored = []
        for pb in playbooks:
            score = 0
            searchable_text = " ".join([
                str(pb.get("title", "")),
                str(pb.get("name", "")),
                str(pb.get("description", "")),
                " ".join(pb.get("tags", [])),
                " ".join(str(t) for t in pb.get("mitre_attack", {}).get("techniques", [])),
                " ".join(str(t) for t in pb.get("tactics", [])),
            ]).lower()

            for token in tokens:
                if token in searchable_text:
                    score += 1

            if score > 0:
                scored.append((score, pb))

        scored.sort(key=lambda x: x[0], reverse=True)
        rows = [pb for _, pb in scored[:20]]

        log.info("playbook_search_done", query=query[:60], hits=len(rows))
        return {
            "rows": rows,
            "columns": ["title", "description", "tags", "mitre_attack", "_file"],
            "total": len(rows),
            "source": "playbooks",
        }

    def get_sigma_rules(self, technique_id: str) -> List[Dict[str, Any]]:
        """Return SIGMA rules mapped to a specific ATT&CK technique."""
        playbooks = self._load_playbooks()
        matching = []
        for pb in playbooks:
            techniques = pb.get("tags", []) + pb.get("mitre_attack", {}).get("techniques", [])
            if any(technique_id.lower() in str(t).lower() for t in techniques):
                matching.append(pb)
        return matching

    def get_query_templates(self, tactic: str) -> List[Dict[str, Any]]:
        """Return pre-approved query templates for a given ATT&CK tactic."""
        playbooks = self._load_playbooks()
        return [
            pb for pb in playbooks
            if tactic.lower() in str(pb.get("tactics", [])).lower()
            and "query_templates" in pb
        ]
