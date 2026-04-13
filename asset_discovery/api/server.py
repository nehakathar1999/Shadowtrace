from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes import router as asset_router
from database.db import engine as asset_engine
from database.models import Base as AssetBase
from scheduler.scan_scheduler import start_scheduler as start_asset_scheduler

app = FastAPI(title="Asset Discovery Engine")

# Allow local/LAN frontend access during development. The existing frontend
# builds the API URL from the current browser hostname, so scans opened from
# http://192.168.x.x:5173 or similar would fail if we only allow localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://shadowtrace.local"
    ],
    allow_origin_regex=r"^https?://("
                       r"localhost|"
                       r"127\.0\.0\.1|"
                       r"0\.0\.0\.0|"
                       r"10\.\d+\.\d+\.\d+|"
                       r"192\.168\.\d+\.\d+|"
                       r"172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+"
                       r")(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Threat backend is optional during local scanning. If its DB is down or the
# password is wrong, we still want the core `/scan` API to start and respond.
THREAT_BACKEND_ENABLED = False
threat_start_scheduler = None
threat_stop_scheduler = None

try:
    from threat_backend.routers import router as threat_router
    from threat_backend.tasks import start_scheduler as threat_start_scheduler, stop_scheduler as threat_stop_scheduler
    from threat_backend.database import Base as ThreatBase, engine as threat_engine
    import threat_backend.models.orm_models  # noqa: F401
    THREAT_BACKEND_ENABLED = True
except Exception as exc:
    threat_router = None
    ThreatBase = None
    threat_engine = None
    print(f"[asset_discovery] Threat backend disabled at startup: {exc}")

@app.on_event("startup")
def on_startup():
    # Ensure the main asset-discovery tables exist in PostgreSQL.
    AssetBase.metadata.create_all(bind=asset_engine)

    # Create optional threat-intel tables only when that subsystem loaded cleanly.
    if THREAT_BACKEND_ENABLED and ThreatBase is not None and threat_engine is not None:
        ThreatBase.metadata.create_all(bind=threat_engine)

    # Resume persisted scheduled scans for the asset-discovery engine.
    start_asset_scheduler(lambda target, options: __import__("api.routes", fromlist=["_execute_scan"])._execute_scan(target, options=options))

    if THREAT_BACKEND_ENABLED and threat_start_scheduler:
        threat_start_scheduler()

@app.on_event("shutdown")
def on_shutdown():
    if THREAT_BACKEND_ENABLED and threat_stop_scheduler:
        threat_stop_scheduler()

app.include_router(asset_router)

if THREAT_BACKEND_ENABLED and threat_router is not None:
    app.include_router(threat_router)
