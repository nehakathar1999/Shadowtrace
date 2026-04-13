from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from threat_backend.config import settings

database_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

engine = create_engine(
    database_url,
    future=True,
    pool_pre_ping=True,
    echo=str(settings.DEBUG).lower() in {"1", "true", "yes", "debug"},
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
