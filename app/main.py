from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api.routes import router
from app.config import settings
from app.database import Base, engine


STATIC_DIR = Path(__file__).resolve().parent / "static"

app = FastAPI(title=settings.APP_NAME)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def on_startup() -> None:
    # Create tables automatically for the MVP scaffold.
    Base.metadata.create_all(bind=engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE vulnerabilities "
                "ADD COLUMN IF NOT EXISTS external_alert_id VARCHAR(255)"
            )
        )


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


app.include_router(router)
