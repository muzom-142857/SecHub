import re
from pathlib import Path
from typing import Any

import yaml


class Analyzer:
    """Maps ResultStore data against the YAML rule table to produce recommended actions.

    Rules are loaded from all *.yaml files in the rules directory at startup.
    default.yaml ships with the project; custom.yaml (if present) is merged in.
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
        if rules_dir is None:
            rules_dir = Path(__file__).parent.parent / "rules"
        self.rules: list[dict[str, Any]] = []
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: Path) -> None:
        for rules_file in sorted(rules_dir.glob("*.yaml")):
            with rules_file.open() as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    self.rules.extend(data["rules"])

    def analyze(self, result_store: dict[str, Any]) -> list[dict[str, Any]]:
        """Evaluate all rules against result_store; return deduplicated recommendation list."""
        recommendations: list[dict[str, Any]] = []
        seen_actions: set[str] = set()

        open_ports = self._get_open_ports(result_store)
        detected_versions = self._get_versions(result_store)

        # Extract CVSS scores from the cves list stored by Phase 2
        cves = result_store.get("phase2", {}).get("cves", [])
        cvss_scores: list[float] = [
            float(c["cvss_score"]) for c in cves if c.get("cvss_score") is not None
        ]

        obtained_files = result_store.get("phase4", {}).get("obtained_files", [])

        for rule in self.rules:
            condition = rule.get("condition")
            actions = rule.get("actions", [])
            matched = False

            if condition == "port_open":
                rule_ports = set(rule.get("ports", []))
                if rule_ports & open_ports:
                    matched = True

            elif condition == "service_version_detected":
                matched = bool(detected_versions)

            elif condition == "version_match":
                pattern = rule.get("pattern", "")
                matched = any(
                    re.search(pattern, v, re.IGNORECASE) for v in detected_versions
                )

            elif condition == "cvss_gte":
                threshold = float(rule.get("value", 7.0))
                matched = any(s >= threshold for s in cvss_scores)

            elif condition == "exploit_available":
                matched = bool(result_store.get("phase2", {}).get("exploits"))

            elif condition == "web_service_detected":
                matched = bool(open_ports & {80, 443, 8080, 8443})

            elif condition == "file_obtained":
                pattern = rule.get("pattern", "")
                matched = any(pattern in f for f in obtained_files)

            elif condition == "hash_detected":
                matched = bool(result_store.get("phase4", {}).get("hashes"))

            if matched:
                for action in actions:
                    if action not in seen_actions:
                        seen_actions.add(action)
                        recommendations.append({
                            "action": action,
                            "rule_id": rule.get("id"),
                            "description": rule.get("description", ""),
                            "cve": rule.get("cve"),
                        })

        return recommendations

    def _get_open_ports(self, result_store: dict[str, Any]) -> set[int]:
        return {
            p["port"]
            for p in result_store.get("phase1", {}).get("ports", [])
            if p.get("state") == "open"
        }

    def _get_versions(self, result_store: dict[str, Any]) -> list[str]:
        return [
            f"{p.get('service', '')} {p.get('version', '')}".strip()
            for p in result_store.get("phase1", {}).get("ports", [])
            if p.get("version")
        ]
