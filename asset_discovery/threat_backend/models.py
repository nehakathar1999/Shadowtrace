from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(4000), nullable=True)
    published_date = Column(DateTime, nullable=True, index=True)
    last_modified = Column(DateTime, nullable=True)
    cvss_score = Column(Float, default=0.0, index=True)
    severity = Column(String(20), default="NONE", index=True)
    cvss_v3 = Column(JSON, nullable=True)
    cwe_ids = Column(ARRAY(String), nullable=True, default=[])
    references = Column(JSON, nullable=True, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    exploit_links = relationship("ExploitCVELink", back_populates="cve", cascade="all, delete-orphan")

class Exploit(Base):
    __tablename__ = "exploits"
    id = Column(Integer, primary_key=True, index=True)
    exploit_id = Column(String(100), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(String(4000), nullable=True)
    platform = Column(String(100), nullable=True)
    date = Column(DateTime, nullable=True, index=True)
    url = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cve_links = relationship("ExploitCVELink", back_populates="exploit", cascade="all, delete-orphan")

class ExploitCVELink(Base):
    __tablename__ = "exploit_cve_links"
    id = Column(Integer, primary_key=True, index=True)
    exploit_id = Column(String(100), ForeignKey("exploits.exploit_id", ondelete="CASCADE"), nullable=False)
    cve_id = Column(String(50), ForeignKey("cves.cve_id", ondelete="CASCADE"), nullable=False)
    __table_args__ = (UniqueConstraint('exploit_id', 'cve_id', name='uq_exploit_cve'),)

    exploit = relationship("Exploit", back_populates="cve_links")
    cve = relationship("CVE", back_populates="exploit_links")

