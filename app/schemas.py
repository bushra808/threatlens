from datetime import datetime

from pydantic import BaseModel, ConfigDict


class VulnerabilityBase(BaseModel):
    source: str
    repository: str
    vulnerability_id: str
    package_name: str
    severity: str
    cvss_score: float | None = None
    category: str | None = None
    status: str
    priority: str
    title: str
    description: str | None = None
    detected_at: datetime
    last_seen_at: datetime


class VulnerabilityRead(VulnerabilityBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class AutomationEventBase(BaseModel):
    vulnerability_id: int
    action_type: str
    destination: str
    status: str
    message: str


class AutomationEventRead(AutomationEventBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IngestResponse(BaseModel):
    processed: int
    inserted: int
    updated: int
    remediated: int
    unchanged: int


class SummaryResponse(BaseModel):
    total_vulnerabilities: int
    open_vulnerabilities: int
    by_severity: dict[str, int]
    by_priority: dict[str, int]


class AutomationRunResponse(BaseModel):
    processed_critical_findings: int
    events_created: int
    skipped_existing: int
    results: list[dict[str, str | int]]
