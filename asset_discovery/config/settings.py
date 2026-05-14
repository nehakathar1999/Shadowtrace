import os

class Settings:
    NETWORK_RANGE = "192.168.1.0/24"

    DATABASE_URL = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:Berry@localhost:5432/vaptScanner"
    )

    SCAN_TIMEOUT = 2
    MAX_THREADS = 50
    FAST_SCAN_MODE = os.getenv("FAST_SCAN_MODE", "true").lower() == "true"
    ENABLE_LIVE_NVD_LOOKUPS = os.getenv("ENABLE_LIVE_NVD_LOOKUPS", "false").lower() == "true"
    SERVICE_SCAN_TIMEOUT = int(os.getenv("SERVICE_SCAN_TIMEOUT", "20"))
    OS_SCAN_TIMEOUT = int(os.getenv("OS_SCAN_TIMEOUT", "12"))
    TRAFFIC_SNIFF_SECONDS = int(os.getenv("TRAFFIC_SNIFF_SECONDS", "6"))
    ENABLE_TRAFFIC_SNIFFING = os.getenv("ENABLE_TRAFFIC_SNIFFING", "true").lower() == "true"
    ENABLE_SSH_CREDENTIAL_SCAN = os.getenv("ENABLE_SSH_CREDENTIAL_SCAN", "false").lower() == "true"
    DEFAULT_SCAN_INTERVAL_MINUTES = int(os.getenv("DEFAULT_SCAN_INTERVAL_MINUTES", "1440"))

settings = Settings()   
