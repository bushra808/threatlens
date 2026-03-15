from fastapi import FastAPI
from sqlalchemy import text

from app.api.routes import router
from app.config import settings
from app.database import Base, engine


app = FastAPI(title=settings.APP_NAME)


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


app.include_router(router)
