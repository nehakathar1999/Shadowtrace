from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class CVSSMetrics(BaseModel):
    version: str
    vector_string: Optional[str] = None
    base_score: float = 0.0
    base_severity: str = "NONE"
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

class CVEReference(BaseModel):
    url: str
    source: Optional[str] = None
    tags: List[str] = []

class AffectedProduct(BaseModel):
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    version_end: Optional[str] = None

class CVEModel(BaseModel):
    cve_id: str
    description: str = ""
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    cvss_score: float = 0.0
    cvss_v3: Optional[CVSSMetrics] = None
    cvss_v2: Optional[CVSSMetrics] = None
    severity: str = "NONE"
    cwe_ids: List[str] = []
    affected_products: List[AffectedProduct] = []
    references: List[CVEReference] = []
    has_exploit: bool = False
    exploit_ids: List[str] = []
    mitre_technique_ids: List[str] = []
    fetched_at: datetime = Field(default_factory=datetime.utcnow)

class CVEFilter(BaseModel):
    severity: Optional[str] = None
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    has_exploit: Optional[bool] = None
    keyword: Optional[str] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    page: int = 1
    page_size: int = 20

class CVEListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    data: List[CVEModel]

