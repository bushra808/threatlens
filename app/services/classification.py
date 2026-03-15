SEVERITY_PRIORITY_MAP = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}


def classify_priority(severity: str) -> str:
    """Map vendor severity values into a simple internal priority."""

    return SEVERITY_PRIORITY_MAP.get(severity.lower(), "P4")
