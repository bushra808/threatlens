import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import Vulnerability
from app.services.normalization import normalize_dependabot_alert


MOCK_DATA_FILE = Path(__file__).resolve().parents[2] / "mock_data" / "dependabot_alerts.json"


def load_dependabot_alerts(file_path: Path | None = None) -> list[dict]:
    source_file = file_path or MOCK_DATA_FILE
    with source_file.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def ingest_dependabot_alerts(db: Session, file_path: Path | None = None) -> dict[str, int]:
    raw_alerts = load_dependabot_alerts(file_path=file_path)
    inserted = 0
    updated = 0

    for raw_alert in raw_alerts:
        normalized = normalize_dependabot_alert(raw_alert)

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
            existing.last_seen_at = normalized["last_seen_at"]
            existing.status = "open"
            updated += 1
            continue

        db.add(Vulnerability(**normalized))
        inserted += 1

    db.commit()

    return {
        "processed": len(raw_alerts),
        "inserted": inserted,
        "updated": updated,
    }
