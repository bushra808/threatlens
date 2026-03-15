import json
from pathlib import Path

import requests
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AutomationEvent, Vulnerability


RULES_FILE = Path(__file__).resolve().parents[2] / "mock_data" / "rules.json"
DEDUPED_EVENT_STATUSES = {"sent", "created", "simulated"}


def load_rules() -> dict:
    with RULES_FILE.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def build_destination_error(prefix: str, response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}

    message = payload.get("message") or response.text or "Request failed."
    return f"{prefix} failed with HTTP {response.status_code}: {message}"


def send_slack_alert(vulnerability: Vulnerability) -> tuple[str, str]:
    message = (
        f"[ThreatLens] Critical vulnerability in {vulnerability.repository}: "
        f"{vulnerability.title} ({vulnerability.package_name}, {vulnerability.vulnerability_id})"
    )

    if not settings.SLACK_WEBHOOK_URL:
        return "simulated", "Slack webhook not configured. Alert was simulated."

    try:
        response = requests.post(
            settings.SLACK_WEBHOOK_URL,
            json={"text": message},
            timeout=10,
        )
        if not response.ok:
            return "failed", build_destination_error("Slack alert", response)
        return "sent", "Slack alert sent successfully."
    except requests.RequestException as exc:
        return "failed", f"Slack alert failed: {exc}"


def create_jira_ticket(vulnerability: Vulnerability) -> tuple[str, str]:
    summary = f"[ThreatLens] Critical vulnerability in {vulnerability.repository}"
    description = (
        f"Package: {vulnerability.package_name}\n"
        f"Severity: {vulnerability.severity}\n"
        f"Priority: {vulnerability.priority}\n"
        f"Identifier: {vulnerability.vulnerability_id}\n"
        f"Title: {vulnerability.title}\n"
        f"Description: {vulnerability.description}"
    )

    required_settings = [
        settings.JIRA_BASE_URL,
        settings.JIRA_USER_EMAIL,
        settings.JIRA_API_TOKEN,
        settings.JIRA_PROJECT_KEY,
    ]
    if not all(required_settings):
        return "simulated", "Jira configuration missing. Ticket creation was simulated."

    try:
        response = requests.post(
            f"{settings.JIRA_BASE_URL.rstrip('/')}/rest/api/2/issue",
            auth=(settings.JIRA_USER_EMAIL, settings.JIRA_API_TOKEN),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={
                "fields": {
                    "project": {"key": settings.JIRA_PROJECT_KEY},
                    "summary": summary,
                    "description": description,
                    "issuetype": {"name": "Task"},
                }
            },
            timeout=10,
        )
        if not response.ok:
            return "failed", build_destination_error("Jira ticket creation", response)
        return "created", "Jira ticket created successfully."
    except requests.RequestException as exc:
        return "failed", f"Jira ticket creation failed: {exc}"


def log_automation_event(
    db: Session,
    vulnerability: Vulnerability,
    action_type: str,
    destination: str,
    status: str,
    message: str,
) -> AutomationEvent:
    event = AutomationEvent(
        vulnerability_id=vulnerability.id,
        action_type=action_type,
        destination=destination,
        status=status,
        message=message,
    )
    db.add(event)
    db.flush()
    return event


def automation_already_recorded(db: Session, vulnerability: Vulnerability, action_type: str) -> bool:
    return (
        db.query(AutomationEvent.id)
        .filter(
            and_(
                AutomationEvent.vulnerability_id == vulnerability.id,
                AutomationEvent.action_type == action_type,
                AutomationEvent.status.in_(DEDUPED_EVENT_STATUSES),
                AutomationEvent.created_at >= vulnerability.last_seen_at,
            )
        )
        .first()
        is not None
    )


def run_critical_automations(db: Session) -> dict:
    rules = load_rules()
    critical_actions = rules.get("critical", [])
    critical_findings = (
        db.query(Vulnerability)
        .filter(Vulnerability.severity == "critical", Vulnerability.status == "open")
        .all()
    )

    results = []
    events_created = 0
    skipped_existing = 0

    for vulnerability in critical_findings:
        for action in critical_actions:
            if automation_already_recorded(db, vulnerability, action):
                skipped_existing += 1
                results.append(
                    {
                        "vulnerability_id": vulnerability.id,
                        "action_type": action,
                        "status": "skipped",
                        "message": "Existing automation already recorded for this open finding.",
                    }
                )
                continue

            if action == "slack_alert":
                status, message = send_slack_alert(vulnerability)
                destination = "slack"
            elif action == "jira_ticket":
                status, message = create_jira_ticket(vulnerability)
                destination = "jira"
            else:
                status, message = "skipped", f"Unsupported automation action: {action}"
                destination = action

            event = log_automation_event(
                db=db,
                vulnerability=vulnerability,
                action_type=action,
                destination=destination,
                status=status,
                message=message,
            )
            events_created += 1
            results.append(
                {
                    "event_id": event.id,
                    "vulnerability_id": vulnerability.id,
                    "action_type": action,
                    "status": status,
                }
            )

    db.commit()

    return {
        "processed_critical_findings": len(critical_findings),
        "events_created": events_created,
        "skipped_existing": skipped_existing,
        "results": results,
    }
