from datetime import datetime, timezone

from app.services.classification import classify_priority


GITHUB_STATE_STATUS_MAP = {
    "open": "open",
    "fixed": "remediated",
    "dismissed": "false_positive",
    "auto_dismissed": "false_positive",
}


def parse_datetime(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def map_github_state_to_status(state: str | None) -> str:
    return GITHUB_STATE_STATUS_MAP.get((state or "open").lower(), "open")


def normalize_dependabot_alert(raw_alert: dict) -> dict:
    """Convert a Dependabot-style alert into the ThreatLens schema."""

    advisory = raw_alert.get("security_advisory", {})
    dependency = raw_alert.get("dependency", {})
    package = dependency.get("package", {})
    cwes = advisory.get("cwes", [])
    severity = advisory.get("severity", "low").lower()
    source_state = raw_alert.get("state", "open")

    category = "dependency-vulnerability"
    if cwes:
        category = cwes[0].get("cwe_id") or category

    return {
        "external_alert_id": str(raw_alert.get("number") or raw_alert.get("id")) if raw_alert.get("number") or raw_alert.get("id") else None,
        "source": "dependabot",
        "repository": raw_alert.get("repository", "unknown-repository"),
        "vulnerability_id": advisory.get("ghsa_id", f"dependabot-{raw_alert.get('id', 'unknown')}"),
        "package_name": package.get("name", "unknown-package"),
        "severity": severity,
        "cvss_score": advisory.get("cvss", {}).get("score"),
        "category": category,
        "status": map_github_state_to_status(source_state),
        "priority": classify_priority(severity),
        "title": advisory.get("summary", "Untitled vulnerability"),
        "description": advisory.get("description", ""),
        "detected_at": parse_datetime(raw_alert.get("created_at")),
        "last_seen_at": parse_datetime(raw_alert.get("updated_at") or raw_alert.get("created_at")),
    }
