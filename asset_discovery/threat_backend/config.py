import os

from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # PostgreSQL Database
    DATABASE_URL: str = os.getenv(
        "THREAT_DATABASE_URL",
        os.getenv(
            "DATABASE_URL",
            "postgresql://postgres:Berry@localhost:5432/vaptScanner",
        ).replace("postgresql://", "postgresql+asyncpg://", 1),
    )

    # NVD API
    NVD_API_KEY: Optional[str] = None
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # ExploitDB
    EXPLOITDB_CSV_URL: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    # MITRE ATT&CK
    MITRE_ATTACK_URL: str = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

    # Data Retention
    DATA_RETENTION_DAYS: int = 30

    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000", "http://localhost:80", "http://frontend:3000"]

    # App
    APP_NAME: str = "AVAVM Threat Intelligence Engine"
    APP_VERSION: str = "1.0.0"
    DEBUG: str | bool = False

    class Config:
        env_file = ".env"

settings = Settings()

