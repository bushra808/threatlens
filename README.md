# ThreatLens

ThreatLens is a beginner-friendly MVP backend scaffold for a small internal security automation platform. It fetches Dependabot vulnerability findings from GitHub or ingests mock data, normalizes them into a shared schema, stores them in PostgreSQL, classifies priority, exposes simple APIs, and logs automation actions for critical findings.

## Project overview

This scaffold is intentionally simple:

- FastAPI provides the HTTP API.
- SQLAlchemy handles synchronous PostgreSQL access.
- Pydantic schemas shape API responses.
- Dependabot alerts can be fetched from the GitHub REST API.
- Mock Dependabot alerts remain available as a local fallback.
- Critical findings trigger Slack and Jira placeholder automations.
- Every automation run is logged in the database.

## Architecture flow

1. `POST /ingest/dependabot` fetches Dependabot alerts from GitHub when repo settings are configured. Otherwise, it falls back to `mock_data/dependabot_alerts.json`.
2. The ingestion service normalizes each raw alert into a common ThreatLens vulnerability shape.
3. Priority is assigned using a simple severity-to-priority mapping.
4. Findings are deduplicated by `repository + vulnerability_id + package_name + source`.
5. New findings are inserted into PostgreSQL. Existing unchanged findings are left alone, changed findings are updated, GitHub `fixed` alerts become `remediated`, and GitHub `dismissed` or `auto_dismissed` alerts become `false_positive`.
6. `POST /automations/run` finds critical vulnerabilities and runs the actions defined in `mock_data/rules.json`.
7. Slack and Jira actions are deduplicated so repeated automation runs do not recreate the same action for the same open finding.
8. Each real automation action creates an `AutomationEvent` row, even when the action is simulated.

## Folder structure

```text
threatlens/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── models.py
│   ├── schemas.py
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py
│   └── services/
│       ├── __init__.py
│       ├── ingestion.py
│       ├── normalization.py
│       ├── classification.py
│       └── automation.py
├── mock_data/
│   ├── dependabot_alerts.json
│   └── rules.json
├── requirements.txt
├── .env.example
└── README.md
```

## What each file does

- `app/main.py`: creates the FastAPI app, registers routes, and creates database tables on startup.
- `app/config.py`: loads environment variables from `.env` and exposes app settings.
- `app/database.py`: configures the SQLAlchemy engine, session factory, and base model class.
- `app/models.py`: defines the `Vulnerability` and `AutomationEvent` database tables.
- `app/schemas.py`: defines response models for the API.
- `app/api/routes.py`: exposes the health, ingest, list, summary, automation, and event endpoints.
- `app/services/ingestion.py`: fetches Dependabot alerts from GitHub or reads mock data, normalizes them, stores only meaningful changes, and marks missing findings as `remediated`.
- `app/services/normalization.py`: converts raw Dependabot-style alerts into the internal schema.
- `app/services/classification.py`: maps severity values to simple priorities (`P1` to `P4`).
- `app/services/automation.py`: loads rules, runs Slack and Jira placeholder actions, and logs automation events.
- `mock_data/dependabot_alerts.json`: sample vulnerability findings for the `brokencrystals` demo repository.
- `mock_data/rules.json`: simple automation rules for critical findings.
- `.env.example`: starter environment variables for local development.
- `requirements.txt`: Python dependencies for the MVP.

## Setup instructions

### 0. Install local prerequisites

ThreatLens expects Python 3.11 and PostgreSQL.

If those commands are missing on macOS with Homebrew, install them first:

```bash
brew install python@3.11 postgresql@16
brew services start postgresql@16
```

After installation, verify the tools are available:

```bash
python3.11 --version
pip3 --version
psql --version
```

### 1. Create the PostgreSQL database

Make sure PostgreSQL is installed and running locally. Then create the database:

```bash
createdb threatlens
```

If you want to create it from `psql` instead:

```sql
CREATE DATABASE threatlens;
```

### 2. Create and activate a virtual environment

```bash
cd threatlens
python3.11 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example file and update values as needed:

```bash
cp .env.example .env
```

Minimum required setting:

- `DATABASE_URL=postgresql:///threatlens`

For GitHub ingestion, also set:

- `GITHUB_TOKEN`
- `GITHUB_OWNER`
- `GITHUB_REPO`

GitHub token requirements for the repository Dependabot alerts endpoint:

- classic PAT: `security_events` scope
- fine-grained PAT: repository permission `Dependabot alerts: Read`

If `GITHUB_OWNER` and `GITHUB_REPO` are left empty, ThreatLens falls back to the local mock JSON file.

Slack and Jira settings are optional. If they are missing, ThreatLens simulates those actions and still records `AutomationEvent` rows.

### 5. Run the application

```bash
uvicorn app.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

Swagger UI will be available at `http://127.0.0.1:8000/docs`.

## Troubleshooting

- `python3.11: command not found`: install Python 3.11 with Homebrew and restart your shell.
- `source .venv/bin/activate` fails: the virtual environment was never created because the earlier Python command failed.
- `pip` or `uvicorn` not found: activate the virtual environment first, then install dependencies with `pip install -r requirements.txt`.
- `createdb` or `psql` not found: PostgreSQL client tools are not installed or not on your `PATH`.
- If Homebrew installed Python or PostgreSQL but the shell still cannot find them, run:

```bash
echo 'export PATH="/opt/homebrew/opt/python@3.11/bin:/opt/homebrew/opt/postgresql@16/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

## API endpoints

- `GET /health`: basic app and database health check.
- `GET /`: built-in dashboard UI with selectable widgets.
- `POST /ingest/dependabot`: fetches Dependabot alerts from GitHub or falls back to mock data.
- `GET /vulnerabilities`: lists stored vulnerability records and supports `severity`, `priority`, `repository`, and `status` filters.
- `GET /summary`: returns totals grouped by severity and priority.
- `POST /automations/run`: runs the configured automations for critical findings.
- `GET /automation-events`: lists logged automation events.

## Example local workflow

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/ingest/dependabot
curl -X POST "http://127.0.0.1:8000/ingest/dependabot?owner=my-org&repo=my-repo"
curl -X POST "http://127.0.0.1:8000/ingest/dependabot?use_mock=true"
curl http://127.0.0.1:8000/vulnerabilities
curl "http://127.0.0.1:8000/vulnerabilities?severity=critical&status=open"
curl "http://127.0.0.1:8000/vulnerabilities?repository=Vulnerable-Repositories/brokencrystals&priority=P1"
curl http://127.0.0.1:8000/summary
curl -X POST http://127.0.0.1:8000/automations/run
curl http://127.0.0.1:8000/automation-events
```

## Dashboard UI

ThreatLens includes a lightweight built-in dashboard served from the FastAPI app itself.

- Open `http://127.0.0.1:8000/` in your browser.
- Use the widget dropdown to add cards like summary, open critical findings, remediated findings, and recent automation events.
- Use repository, severity, and status filters to narrow the findings widgets.
- Use the `Run Automations` button to trigger Slack/Jira actions directly from the dashboard.

## GitHub Dependabot ingestion

ThreatLens now supports fetching repository Dependabot alerts directly from GitHub.

Default behavior:

- if `GITHUB_OWNER` and `GITHUB_REPO` are configured, `POST /ingest/dependabot` pulls from GitHub
- if they are not configured, the app uses `mock_data/dependabot_alerts.json`

Optional query parameters:

- `owner`: override the configured GitHub owner for this request
- `repo`: override the configured GitHub repo for this request
- `use_mock=true`: skip GitHub and force mock ingestion

Ingestion behavior:

- if a finding is new, it is inserted
- if the same finding comes back unchanged, no database update is made
- if a stored finding is no longer returned by the latest scan, it is marked `remediated`
- GitHub `fixed` alerts map to ThreatLens `remediated`
- GitHub `dismissed` and `auto_dismissed` alerts map to ThreatLens `false_positive`
- if a `critical` finding has already triggered Slack or Jira for its current open state, repeated automation runs skip that action

Example `.env`:

```env
DATABASE_URL=postgresql:///threatlens
GITHUB_TOKEN=ghp_your_token_here
GITHUB_OWNER=your-org
GITHUB_REPO=your-repo
```

## Next steps

- Add create and update APIs instead of ingesting only from a local file.
- Add proper database migrations with Alembic.
- Add tests for ingestion, normalization, and automation logic.
- Improve Jira ticket payloads and Slack message formatting.
- Add authentication and role-based access control.
- Support more sources beyond Dependabot.
- Prevent duplicate automation runs for the same vulnerability and action.
