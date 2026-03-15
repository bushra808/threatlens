import json
from pathlib import Path

import requests
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Vulnerability
from app.services.normalization import normalize_dependabot_alert


MOCK_DATA_FILE = Path(__file__).resolve().parents[2] / "mock_data" / "dependabot_alerts.json"


def vulnerability_key_from_dict(vulnerability: dict) -> tuple[str, str, str, str]:
    return (
        vulnerability["repository"],
        vulnerability["vulnerability_id"],
        vulnerability["package_name"],
        vulnerability["source"],
    )


def vulnerability_key_from_model(vulnerability: Vulnerability) -> tuple[str, str, str, str]:
    return (
        vulnerability.repository,
        vulnerability.vulnerability_id,
        vulnerability.package_name,
        vulnerability.source,
    )


def load_dependabot_alerts(file_path: Path | None = None) -> list[dict]:
    source_file = file_path or MOCK_DATA_FILE
    with source_file.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def fetch_dependabot_alerts_from_github(owner: str, repo: str, token: str) -> list[dict]:
    """Fetch Dependabot alerts for a repository using the GitHub REST API."""

    if not token:
        raise ValueError("GITHUB_TOKEN is required to fetch Dependabot alerts from GitHub.")

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": settings.GITHUB_API_VERSION,
    }
    url = f"{settings.GITHUB_API_URL.rstrip('/')}/repos/{owner}/{repo}/dependabot/alerts"
    params = {
        "state": "open,fixed,dismissed,auto_dismissed",
        "per_page": 100,
        "direction": "desc",
    }

    alerts: list[dict] = []

    while url:
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        page_alerts = response.json()

        for alert in page_alerts:
            alert["repository"] = f"{owner}/{repo}"

        alerts.extend(page_alerts)
        url = response.links.get("next", {}).get("url")
        params = None

    return alerts


def get_dependabot_alerts(
    owner: str | None = None,
    repo: str | None = None,
    file_path: Path | None = None,
    use_mock: bool = False,
) -> list[dict]:
    if use_mock:
        return load_dependabot_alerts(file_path=file_path)

    github_owner = owner or settings.GITHUB_OWNER
    github_repo = repo or settings.GITHUB_REPO

    if github_owner and github_repo:
        return fetch_dependabot_alerts_from_github(
            owner=github_owner,
            repo=github_repo,
            token=settings.GITHUB_TOKEN or "",
        )

    return load_dependabot_alerts(file_path=file_path)


def apply_vulnerability_changes(existing: Vulnerability, normalized: dict) -> bool:
    """Update only when the incoming alert meaningfully changes the stored record."""

    changed = False

    if existing.status != normalized["status"]:
        existing.status = normalized["status"]
        changed = True

    for field_name in [
        "severity",
        "cvss_score",
        "category",
        "priority",
        "title",
        "description",
    ]:
        incoming_value = normalized[field_name]
        if getattr(existing, field_name) != incoming_value:
            setattr(existing, field_name, incoming_value)
            changed = True

    if changed and existing.last_seen_at != normalized["last_seen_at"]:
        existing.last_seen_at = normalized["last_seen_at"]

    return changed


def ingest_dependabot_alerts(
    db: Session,
    owner: str | None = None,
    repo: str | None = None,
    file_path: Path | None = None,
    use_mock: bool = False,
) -> dict[str, int]:
    raw_alerts = get_dependabot_alerts(
        owner=owner,
        repo=repo,
        file_path=file_path,
        use_mock=use_mock,
    )
    inserted = 0
    updated = 0
    remediated = 0
    unchanged = 0
    current_scan_keys: set[tuple[str, str, str, str]] = set()
    repositories_in_scope = set()

    github_owner = owner or settings.GITHUB_OWNER
    github_repo = repo or settings.GITHUB_REPO
    if not use_mock and github_owner and github_repo:
        repositories_in_scope.add(f"{github_owner}/{github_repo}")

    for raw_alert in raw_alerts:
        normalized = normalize_dependabot_alert(raw_alert)
        current_scan_keys.add(vulnerability_key_from_dict(normalized))
        repositories_in_scope.add(normalized["repository"])

        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.repository == normalized["repository"],
                Vulnerability.vulnerability_id == normalized["vulnerability_id"],
                Vulnerability.package_name == normalized["package_name"],
                Vulnerability.source == normalized["source"],
            )
            .first()
        )

        if existing:
            if apply_vulnerability_changes(existing, normalized):
                updated += 1
            else:
                unchanged += 1
            continue

        db.add(Vulnerability(**normalized))
        inserted += 1

    if repositories_in_scope:
        stale_findings = (
            db.query(Vulnerability)
            .filter(
                and_(
                    Vulnerability.source == "dependabot",
                    Vulnerability.repository.in_(repositories_in_scope),
                    Vulnerability.status == "open",
                )
            )
            .all()
        )

        for vulnerability in stale_findings:
            if vulnerability_key_from_model(vulnerability) not in current_scan_keys:
                vulnerability.status = "remediated"
                remediated += 1

    db.commit()

    return {
        "processed": len(raw_alerts),
        "inserted": inserted,
        "updated": updated,
        "remediated": remediated,
        "unchanged": unchanged,
    }
