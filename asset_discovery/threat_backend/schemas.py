from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class CVEBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cvss_score: Optional[float] = 0.0
    severity: Optional[str] = "NONE"
    cwe_ids: Optional[List[str]] = []
    references: Optional[List[str]] = []

class CVECreate(CVEBase):
    pass

class CVEOut(CVEBase):
    id: int
    class Config:
        from_attributes = True

class ExploitBase(BaseModel):
    exploit_id: str
    title: str
    description: Optional[str] = None
    platform: Optional[str] = None
    date: Optional[datetime] = None
    url: Optional[str] = None

class ExploitOut(ExploitBase):
    id: int
    class Config:
        from_attributes = True

