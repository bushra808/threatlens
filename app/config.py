from pathlib import Path
import os

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Simple settings object backed by environment variables."""

    APP_NAME: str = os.getenv("APP_NAME", "ThreatLens")
    APP_ENV: str = os.getenv("APP_ENV", "development")
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql:///threatlens",
    )
    GITHUB_API_URL: str = os.getenv("GITHUB_API_URL", "https://api.github.com")
    GITHUB_API_VERSION: str = os.getenv("GITHUB_API_VERSION", "2022-11-28")
    GITHUB_TOKEN: str | None = os.getenv("GITHUB_TOKEN")
    GITHUB_OWNER: str | None = os.getenv("GITHUB_OWNER")
    GITHUB_REPO: str | None = os.getenv("GITHUB_REPO")
    SLACK_WEBHOOK_URL: str | None = os.getenv("SLACK_WEBHOOK_URL")
    JIRA_BASE_URL: str | None = os.getenv("JIRA_BASE_URL")
    JIRA_USER_EMAIL: str | None = os.getenv("JIRA_USER_EMAIL")
    JIRA_API_TOKEN: str | None = os.getenv("JIRA_API_TOKEN")
    JIRA_PROJECT_KEY: str = os.getenv("JIRA_PROJECT_KEY", "SEC")


settings = Settings()
