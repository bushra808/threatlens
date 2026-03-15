from fastapi import APIRouter, Depends, HTTPException
import requests
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AutomationEvent, Vulnerability
from app.schemas import (
    AutomationEventRead,
    AutomationRunResponse,
    IngestResponse,
    SummaryResponse,
    VulnerabilityRead,
)
from app.services.automation import run_critical_automations
from app.services.ingestion import ingest_dependabot_alerts


router = APIRouter()


@router.get("/health")
def health_check(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok"}
    except Exception as exc:  # pragma: no cover - simple MVP health check
        raise HTTPException(status_code=500, detail=f"Database connection failed: {exc}") from exc


@router.post("/ingest/dependabot", response_model=IngestResponse)
def ingest_dependabot(
    owner: str | None = None,
    repo: str | None = None,
    use_mock: bool = False,
    db: Session = Depends(get_db),
) -> dict[str, int]:
    try:
        return ingest_dependabot_alerts(db, owner=owner, repo=repo, use_mock=use_mock)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except requests.RequestException as exc:
        db.rollback()
        raise HTTPException(status_code=502, detail=f"GitHub API request failed: {exc}") from exc
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {exc}") from exc


@router.get("/vulnerabilities", response_model=list[VulnerabilityRead])
def list_vulnerabilities(
    severity: str | None = None,
    priority: str | None = None,
    repository: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
) -> list[Vulnerability]:
    query = db.query(Vulnerability)

    if severity:
        query = query.filter(Vulnerability.severity == severity.lower())
    if priority:
        query = query.filter(Vulnerability.priority == priority.upper())
    if repository:
        query = query.filter(Vulnerability.repository == repository)
    if status:
        query = query.filter(Vulnerability.status == status.lower())

    return query.order_by(Vulnerability.detected_at.desc(), Vulnerability.id.desc()).all()


@router.get("/summary", response_model=SummaryResponse)
def get_summary(db: Session = Depends(get_db)) -> dict:
    vulnerabilities = db.query(Vulnerability).all()
    severity_rows = (
        db.query(Vulnerability.severity, func.count(Vulnerability.id))
        .group_by(Vulnerability.severity)
        .all()
    )
    priority_rows = (
        db.query(Vulnerability.priority, func.count(Vulnerability.id))
        .group_by(Vulnerability.priority)
        .all()
    )
    open_vulnerabilities = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.status == "open")
        .scalar()
    )

    return {
        "total_vulnerabilities": len(vulnerabilities),
        "open_vulnerabilities": open_vulnerabilities or 0,
        "by_severity": {severity: count for severity, count in severity_rows},
        "by_priority": {priority: count for priority, count in priority_rows},
    }


@router.post("/automations/run", response_model=AutomationRunResponse)
def run_automations(db: Session = Depends(get_db)) -> dict:
    try:
        return run_critical_automations(db)
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Automation run failed: {exc}") from exc


@router.get("/automation-events", response_model=list[AutomationEventRead])
def list_automation_events(db: Session = Depends(get_db)) -> list[AutomationEvent]:
    return (
        db.query(AutomationEvent)
        .order_by(AutomationEvent.created_at.desc(), AutomationEvent.id.desc())
        .all()
    )
