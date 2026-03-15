import json
import time
from pathlib import Path

import requests
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Vulnerability
from app.services.normalization import normalize_dependabot_alert


MOCK_DATA_FILE = Path(__file__).resolve().parents[2] / "mock_data" / "dependabot_alerts.json"
TRANSIENT_GITHUB_STATUS_CODES = {429, 500, 502, 503, 504}


def vulnerability_key_from_dict(vulnerability: dict) -> tuple[str, str]:
    external_alert_id = vulnerability.get("external_alert_id")
    if external_alert_id:
        return (vulnerability["source"], external_alert_id)

    return (
        vulnerability["source"],
        f"{vulnerability['repository']}::{vulnerability['vulnerability_id']}::{vulnerability['package_name']}",
    )


def vulnerability_key_from_model(vulnerability: Vulnerability) -> tuple[str, str]:
    if vulnerability.external_alert_id:
        return (vulnerability.source, vulnerability.external_alert_id)

    return (
        vulnerability.source,
        f"{vulnerability.repository}::{vulnerability.vulnerability_id}::{vulnerability.package_name}",
    )


def load_dependabot_alerts(file_path: Path | None = None) -> list[dict]:
    source_file = file_path or MOCK_DATA_FILE
    with source_file.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def build_github_api_error(response: requests.Response, owner: str, repo: str) -> ValueError:
    status_code = response.status_code

    try:
        payload = response.json()
    except ValueError:
        payload = {}

    message = payload.get("message") or response.text or "GitHub API request failed."
    prefix = f"GitHub Dependabot API error for {owner}/{repo}"

    if status_code == 401:
        return ValueError(f"{prefix}: unauthorized. Check GITHUB_TOKEN.")
    if status_code == 403:
        return ValueError(f"{prefix}: forbidden. Check token permissions or rate limits. {message}")
    if status_code == 404:
        return ValueError(f"{prefix}: repository not found or token cannot access it.")
    if status_code == 429:
        return ValueError(f"{prefix}: rate limited. {message}")
    if status_code >= 500:
        return ValueError(f"{prefix}: GitHub server error ({status_code}). {message}")

    return ValueError(f"{prefix}: HTTP {status_code}. {message}")


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
        last_error: ValueError | None = None

        for attempt in range(2):
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.ok:
                break

            last_error = build_github_api_error(response, owner=owner, repo=repo)
            if response.status_code not in TRANSIENT_GITHUB_STATUS_CODES or attempt == 1:
                raise last_error

            time.sleep(1)
        else:  # pragma: no cover - defensive fallback
            if last_error:
                raise last_error
            raise ValueError(f"GitHub Dependabot API error for {owner}/{repo}: request failed.")

        try:
            page_alerts = response.json()
        except ValueError as exc:
            raise ValueError(
                f"GitHub Dependabot API for {owner}/{repo} returned invalid JSON."
            ) from exc

        if not isinstance(page_alerts, list):
            raise ValueError(
                f"GitHub Dependabot API for {owner}/{repo} returned an unexpected response shape."
            )

        for alert in page_alerts:
            if not isinstance(alert, dict):
                continue
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
        "external_alert_id",
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
    current_scan_keys: set[tuple[str, str]] = set()
    repositories_in_scope = set()

    github_owner = owner or settings.GITHUB_OWNER
    github_repo = repo or settings.GITHUB_REPO
    if not use_mock and github_owner and github_repo:
        repositories_in_scope.add(f"{github_owner}/{github_repo}")

    for raw_alert in raw_alerts:
        normalized = normalize_dependabot_alert(raw_alert)
        current_scan_keys.add(vulnerability_key_from_dict(normalized))
        repositories_in_scope.add(normalized["repository"])

        existing_query = db.query(Vulnerability).filter(Vulnerability.source == normalized["source"])
        if normalized["external_alert_id"]:
            existing_query = existing_query.filter(
                Vulnerability.external_alert_id == normalized["external_alert_id"]
            )
        else:
            existing_query = existing_query.filter(
                Vulnerability.repository == normalized["repository"],
                Vulnerability.vulnerability_id == normalized["vulnerability_id"],
                Vulnerability.package_name == normalized["package_name"],
            )

        existing = existing_query.first()

        if existing:
            if apply_vulnerability_changes(existing, normalized):
                updated += 1
            else:
                unchanged += 1
            continue

        db.add(Vulnerability(**normalized))
        inserted += 1

    should_mark_missing_as_remediated = use_mock or not (github_owner and github_repo)

    if repositories_in_scope and should_mark_missing_as_remediated:
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
