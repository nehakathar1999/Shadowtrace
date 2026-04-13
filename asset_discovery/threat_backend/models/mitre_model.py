from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class MITRETactic(BaseModel):
    tactic_id: str
    name: str
    short_name: str
    description: str = ""
    technique_count: int = 0
    fetched_at: datetime = Field(default_factory=datetime.utcnow)

class MITRETechnique(BaseModel):
    technique_id: str
    name: str
    description: str = ""
    tactic_ids: List[str] = []
    tactic_names: List[str] = []
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    platforms: List[str] = []
    data_sources: List[str] = []
    detection: str = ""
    mitigation: str = ""
    cve_ids: List[str] = []
    url: Optional[str] = None
    fetched_at: datetime = Field(default_factory=datetime.utcnow)

class MITREMatrixResponse(BaseModel):
    tactics: List[MITRETactic]
    techniques: List[MITRETechnique]
    total_tactics: int
    total_techniques: int

class TechniqueFilter(BaseModel):
    tactic_id: Optional[str] = None
    platform: Optional[str] = None
    keyword: Optional[str] = None
    page: int = 1
    page_size: int = 50

