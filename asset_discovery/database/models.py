from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


# ─────────────────────────────────────────────
# SCANS TABLE
# ─────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, unique=True, index=True)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    signup_events = relationship("SignupEvent", back_populates="user")
    login_events = relationship("LoginEvent", back_populates="user")


class SignupEvent(Base):
    __tablename__ = "signup_events"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False, index=True)
    ip_address = Column(String)
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="signup_events")


class LoginEvent(Base):
    __tablename__ = "login_events"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    email = Column(String, nullable=False, index=True)
    ip_address = Column(String)
    user_agent = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="login_events")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    target = Column(String)
    target_type = Column(String)
    status = Column(String)
    active_hosts = Column(Integer)
    total_hosts = Column(Integer)
    total_vulnerabilities = Column(Integer)
    critical_risk = Column(Integer)
    report_json_path = Column(String)
    report_txt_path = Column(String)
    report_pdf_path = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    assets = relationship("Asset", back_populates="scan")
    owasp_results = relationship("OWASPResult", back_populates="scan")


# ─────────────────────────────────────────────
# ASSETS TABLE
# ─────────────────────────────────────────────
class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    target_input = Column(String)
    ip = Column(String)
    hostname = Column(String)
    domain = Column(String)
    mac = Column(String)
    vendor = Column(String)
    device_type = Column(String)
    os_name = Column(String)
    status = Column(String)
    country = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")
    ports = relationship("Port", back_populates="asset")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")
    insecure_protocols = relationship("InsecureProtocol", back_populates="asset")
    tls_issues = relationship("TLSIssue", back_populates="asset")


# ─────────────────────────────────────────────
# PORTS TABLE
# ─────────────────────────────────────────────
class Port(Base):
    __tablename__ = "ports"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port = Column(Integer)
    protocol = Column(String)
    service = Column(String)
    product = Column(String)
    version = Column(String)
    state = Column(String)

    asset = relationship("Asset", back_populates="ports")


# ─────────────────────────────────────────────
# VULNERABILITIES TABLE
# ─────────────────────────────────────────────
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    cve_id = Column(String)
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    cvss_score = Column(Float)
    product = Column(String)
    version = Column(String)
    remediation = Column(Text)
    status = Column(String)
    detected_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="vulnerabilities")


# ─────────────────────────────────────────────
# INSECURE PROTOCOLS TABLE
# ─────────────────────────────────────────────
class InsecureProtocol(Base):
    __tablename__ = "insecure_protocols"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port = Column(Integer)
    protocol = Column(String)
    message = Column(Text)

    asset = relationship("Asset", back_populates="insecure_protocols")


# ─────────────────────────────────────────────
# TLS ISSUES TABLE
# ─────────────────────────────────────────────
class TLSIssue(Base):
    __tablename__ = "tls_issues"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    port = Column(Integer)
    tls_version = Column(String)
    message = Column(Text)

    asset = relationship("Asset", back_populates="tls_issues")


# ─────────────────────────────────────────────
# OWASP RESULTS TABLE
# ─────────────────────────────────────────────
class OWASPResult(Base):
    __tablename__ = "owasp_results"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    category_id = Column(String)
    category_name = Column(String)
    severity = Column(String)
    findings_count = Column(Integer)
    status = Column(String)

    scan = relationship("Scan", back_populates="owasp_results")
    findings = relationship("OWASPFinding", back_populates="owasp_result")


# ─────────────────────────────────────────────
# OWASP FINDINGS TABLE
# ─────────────────────────────────────────────
class OWASPFinding(Base):
    __tablename__ = "owasp_findings"

    id = Column(Integer, primary_key=True)
    owasp_result_id = Column(Integer, ForeignKey("owasp_results.id"))
    title = Column(String)
    description = Column(Text)
    severity = Column(String)
    url = Column(String)
    evidence = Column(Text)

    owasp_result = relationship("OWASPResult", back_populates="findings")
