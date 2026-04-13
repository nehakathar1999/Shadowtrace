"""
SQLAlchemy ORM Models for PostgreSQL
Replaces Pydantic models from MongoDB schema
"""
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
from threat_backend.database import Base

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ CVE Model
class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(4000), nullable=True)
    published_date = Column(DateTime, nullable=True, index=True)
    last_modified = Column(DateTime, nullable=True)
    cvss_score = Column(Float, default=0.0, index=True)
    severity = Column(String(20), default="NONE", index=True)
    
    # CVSS Metrics (stored as JSON)
    cvss_v3 = Column(JSON, nullable=True)
    cvss_v2 = Column(JSON, nullable=True)
    
    # CWE IDs
    cwe_ids = Column(ARRAY(String), nullable=True, default=[])
    
    # Affected products (stored as JSON array)
    affected_products = Column(JSON, nullable=True, default=[])
    
    # References
    references = Column(JSON, nullable=True, default=[])
    
    # Live fetch flag
    live_fetched = Column(Boolean, default=False)
    live_fetched_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    correlations = relationship("ThreatCorrelation", back_populates="cve", cascade="all, delete-orphan")
    exploit_links = relationship("ExploitCVELink", back_populates="cve", cascade="all, delete-orphan")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Exploit Model
class Exploit(Base):
    __tablename__ = "exploits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exploit_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(String(4000), nullable=True)
    exploit_type = Column(String(50), nullable=True)
    platform = Column(String(100), nullable=True)
    date = Column(DateTime, nullable=True, index=True)
    verified = Column(Boolean, default=False)
    source = Column(String(100), nullable=True)
    url = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    cve_links = relationship("ExploitCVELink", back_populates="exploit", cascade="all, delete-orphan")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Exploit-CVE Link
class ExploitCVELink(Base):
    __tablename__ = "exploit_cve_links"

    id = Column(Integer, primary_key=True, autoincrement=True)
    exploit_id = Column(String(100), ForeignKey("exploits.exploit_id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False)
    
    # Relationships
    exploit = relationship("Exploit", back_populates="cve_links")
    cve = relationship("CVE", back_populates="exploit_links")
    
    __table_args__ = (UniqueConstraint('exploit_id', 'cve_id', name='uq_exploit_cve'),)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ MITRE Tactic
class MITRETactic(Base):
    __tablename__ = "mitre_tactics"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tactic_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(String(2000), nullable=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ MITRE Technique
class MITRETechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technique_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(300), nullable=False)
    description = Column(String(4000), nullable=True)
    is_subtechnique = Column(Boolean, default=False)
    platforms = Column(ARRAY(String), nullable=True, default=[])
    tactic_ids = Column(ARRAY(String), nullable=True, default=[])
    tactic_names = Column(ARRAY(String), nullable=True, default=[])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Threat Correlation
class ThreatCorrelation(Base):
    __tablename__ = "threat_correlations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    correlation_id = Column(String(100), unique=True, nullable=False, index=True)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False, index=True)
    cve_description = Column(String(500), nullable=True)
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(20), default="NONE")
    
    # Exploit linkage
    exploit_count = Column(Integer, default=0)
    exploit_ids = Column(ARRAY(String), nullable=True, default=[])
    exploit_verified = Column(Boolean, default=False)
    
    # MITRE linkage
    mitre_technique_ids = Column(ARRAY(String), nullable=True, default=[])
    mitre_technique_names = Column(ARRAY(String), nullable=True, default=[])
    mitre_tactic_names = Column(ARRAY(String), nullable=True, default=[])
    
    # Risk scoring
    risk_score = Column(Float, default=0.0, index=True)
    risk_level = Column(String(20), default="LOW")
    exploit_probability = Column(Float, default=0.0)
    
    # Asset context
    affected_assets = Column(ARRAY(String), nullable=True, default=[])
    asset_criticality = Column(String(20), default="LOW")
    
    # Business impact
    business_impact = Column(String(20), default="LOW")
    active_threat_actors = Column(ARRAY(String), nullable=True, default=[])
    
    # Timestamps
    correlation_timestamp = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    cve = relationship("CVE", back_populates="correlations")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Vulnerability
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vuln_id = Column(String(100), unique=True, nullable=False)
    asset_id = Column(String(100), nullable=False, index=True)
    asset_hostname = Column(String(255), nullable=True)
    asset_ip = Column(String(45), nullable=True)
    asset_type = Column(String(50), default="server")
    criticality = Column(String(20), default="medium")
    cve_id = Column(String(50), nullable=True, index=True)
    name = Column(String(300), nullable=True)
    description = Column(String(4000), nullable=True)
    cvss_score = Column(Float, default=0.0)
    severity = Column(String(20), default="MEDIUM")
    status = Column(String(20), default="open", index=True)
    detected_time = Column(DateTime, default=datetime.utcnow)
    
    # Enriched data
    risk_score = Column(Float, nullable=True)
    exploit_available = Column(Boolean, default=False)
    mitre_techniques = Column(ARRAY(String), nullable=True, default=[])
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Feed Status
class FeedStatus(Base):
    __tablename__ = "feed_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_name = Column(String(50), unique=True, nullable=False, index=True)
    last_run = Column(DateTime, nullable=True)
    status = Column(String(20), default="idle")  # idle | running | success | failed
    records_fetched = Column(Integer, default=0)
    error_message = Column(String(1000), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Feed Log
class FeedLog(Base):
    __tablename__ = "feed_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    feed_type = Column(String(50), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # success | failed
    records_fetched = Column(Integer, default=0)
    error_message = Column(String(1000), nullable=True)
    duration_seconds = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Feed Config
class FeedConfig(Base):
    __tablename__ = "feed_config"

    id = Column(Integer, primary_key=True, autoincrement=True)
    schedule_type = Column(String(20), default="daily")  # realtime | hourly | daily | manual
    enabled = Column(Boolean, default=True)
    last_updated = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ Scanned Host
class ScannedHost(Base):
    __tablename__ = "scanned_hosts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    host_id = Column(String(100), unique=True, nullable=False)
    host = Column(String(45), unique=True, nullable=False)  # IP address
    hostname = Column(String(255), nullable=True)
    os = Column(String(300), nullable=True)
    status = Column(String(20), default="Up")  # Up | Down
    device_type = Column(String(100), nullable=True)
    criticality = Column(String(20), default="LOW")
    detected = Column(String(500), nullable=True)
    open_ports = Column(Integer, default=0)
    total_cves = Column(Integer, default=0)
    
    # Full analysis and raw scan (stored as JSON)
    risk_summary = Column(JSON, nullable=True, default={})
    analysis = Column(JSON, nullable=True)
    raw_scan = Column(JSON, nullable=True)
    
    # Timestamps
    imported_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (Index("idx_host", "host"),)

