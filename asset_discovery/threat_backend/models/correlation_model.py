from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime

# ─── Threat Correlation ───────────────────────────────────────────────
class CorrelationModel(BaseModel):
    correlation_id: str
    cve_id: str
    cve_description: str = ""
    cvss_score: float = 0.0
    severity: str = "NONE"

    # Exploit linkage
    exploit_count: int = 0
    exploit_ids: List[str] = []
    exploit_verified: bool = False

    # MITRE linkage
    mitre_technique_ids: List[str] = []
    mitre_technique_names: List[str] = []
    mitre_tactic_names: List[str] = []

    # AI Risk Score (composite)
    risk_score: float = 0.0              # 0–100
    risk_level: str = "LOW"              # LOW / MEDIUM / HIGH / CRITICAL
    exploit_probability: float = 0.0     # 0–1

    # Asset context (populated when cross-team data arrives)
    affected_assets: List[str] = []
    asset_criticality: str = "LOW"

    # Business impact
    business_impact: str = "LOW"
    active_threat_actors: List[str] = []

    correlation_timestamp: datetime = Field(default_factory=datetime.utcnow)


# ─── Feed Config ──────────────────────────────────────────────────────
class FeedScheduleConfig(BaseModel):
    schedule_type: str = "daily"         # realtime | hourly | daily | manual
    enabled: bool = True
    last_updated: Optional[datetime] = None
    next_run: Optional[datetime] = None

class FeedStatus(BaseModel):
    feed_name: str
    last_run: Optional[datetime] = None
    status: str = "idle"                 # idle | running | success | failed
    records_fetched: int = 0
    error_message: Optional[str] = None

class FeedLog(BaseModel):
    feed_type: str
    status: str
    records_fetched: int = 0
    error_message: Optional[str] = None
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ─── Mock Vulnerability (until other team provides real data) ─────────
class VulnerabilityModel(BaseModel):
    vuln_id: str
    asset_id: str
    asset_hostname: str = ""
    asset_ip: str = ""
    asset_type: str = "server"
    criticality: str = "medium"          # low / medium / high / critical
    cve_id: Optional[str] = None
    name: str = ""
    description: str = ""
    cvss_score: float = 0.0
    severity: str = "MEDIUM"
    status: str = "open"                 # open / in_progress / resolved
    detected_time: datetime = Field(default_factory=datetime.utcnow)
    # Enriched by correlation engine
    risk_score: Optional[float] = None
    exploit_available: bool = False
    mitre_techniques: List[str] = []


# ─── Dashboard Stats ──────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_cves: int = 0
    critical_cves: int = 0
    high_cves: int = 0
    medium_cves: int = 0
    low_cves: int = 0
    total_exploits: int = 0
    verified_exploits: int = 0
    total_techniques: int = 0
    total_tactics: int = 0
    total_correlations: int = 0
    critical_correlations: int = 0
    high_risk_correlations: int = 0
    cves_with_exploits: int = 0
    feed_statuses: List[FeedStatus] = []
    last_updated: Optional[datetime] = None

    # Trend data (last 7 days)
    cve_trend: List[Dict] = []
    severity_distribution: Dict = {}
    top_affected_products: List[Dict] = []
    top_mitre_tactics: List[Dict] = []

