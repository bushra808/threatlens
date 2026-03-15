# ThreatLens

ThreatLens is a beginner-friendly MVP backend scaffold for a small internal security automation platform. It ingests Dependabot vulnerability findings, normalizes them into a shared schema, stores them in PostgreSQL, classifies priority, exposes simple APIs, and logs automation actions for critical findings.

## Project overview

This scaffold is intentionally simple:

- FastAPI provides the HTTP API.
- SQLAlchemy handles synchronous PostgreSQL access.
- Pydantic schemas shape API responses.
- Mock Dependabot alerts are loaded from local JSON.
- Critical findings trigger Slack and Jira placeholder automations.
- Every automation run is logged in the database.

## Architecture flow

1. `POST /ingest/dependabot` loads mock alerts from `mock_data/dependabot_alerts.json`.
2. The ingestion service normalizes each raw alert into a common ThreatLens vulnerability shape.
3. Priority is assigned using a simple severity-to-priority mapping.
4. Findings are deduplicated by `repository + vulnerability_id + package_name + source`.
5. New findings are inserted into PostgreSQL. Existing findings get `last_seen_at` updated and stay `open`.
6. If any finding doesn't come in next scan then it is marked `remediated`
7. `POST /automations/run` finds critical vulnerabilities and runs the actions defined in `mock_data/rules.json`.
8. Each Slack or Jira action creates an `AutomationEvent` row, even when the action is simulated.

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
- `app/services/ingestion.py`: reads mock Dependabot data, normalizes it, deduplicates it, and stores it.
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

- `DATABASE_URL=postgresql://postgres:postgres@localhost:5432/threatlens`

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
- `POST /ingest/dependabot`: loads the mock Dependabot alerts into PostgreSQL.
- `GET /vulnerabilities`: lists stored vulnerability records.
- `GET /summary`: returns totals grouped by severity and priority.
- `POST /automations/run`: runs the configured automations for critical findings.
- `GET /automation-events`: lists logged automation events.

## Example local workflow

```bash
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/ingest/dependabot
curl http://127.0.0.1:8000/vulnerabilities
curl http://127.0.0.1:8000/summary
curl -X POST http://127.0.0.1:8000/automations/run
curl http://127.0.0.1:8000/automation-events
```

## Next steps

- Add create and update APIs instead of ingesting only from a local file.
- Add proper database migrations with Alembic.
- Add tests for ingestion, normalization, and automation logic.
- Improve Jira ticket payloads and Slack message formatting.
- Add authentication and role-based access control.
- Support more sources beyond Dependabot.
- Prevent duplicate automation runs for the same vulnerability and action.
