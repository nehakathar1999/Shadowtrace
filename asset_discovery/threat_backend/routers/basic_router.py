import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from threat_backend.database import get_db
from threat_backend.models.orm_models import CVE, Exploit
from threat_backend.schemas import CVECreate, CVEOut, ExploitBase, ExploitOut

router = APIRouter(prefix="/api/threat", tags=["Threat Intelligence"])
logger = logging.getLogger(__name__)

@router.get("/cves", response_model=list[CVEOut])
def read_cves(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    try:
        return db.query(CVE).offset(skip).limit(limit).all()
    except Exception:
        logger.exception("Failed to read CVEs from threat backend")
        return []


@router.post("/cves", response_model=CVEOut)
def create_cve(cve: CVECreate, db: Session = Depends(get_db)):
    existing = db.query(CVE).filter(CVE.cve_id == cve.cve_id).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"CVE {cve.cve_id} already exists")

    db_obj = CVE(**cve.model_dump())
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj


@router.get("/cves/{cve_id}", response_model=CVEOut)
def read_cve(cve_id: str, db: Session = Depends(get_db)):
    db_obj = db.query(CVE).filter(CVE.cve_id == cve_id).first()
    if not db_obj:
        raise HTTPException(status_code=404, detail="CVE not found")
    return db_obj


@router.get("/exploits", response_model=list[ExploitOut])
def read_exploits(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    return db.query(Exploit).offset(skip).limit(limit).all()


@router.post("/exploits", response_model=ExploitOut)
def create_exploit(exploit: ExploitBase, db: Session = Depends(get_db)):
    db_obj = Exploit(**exploit.model_dump())
    db.add(db_obj)
    db.commit()
    db.refresh(db_obj)
    return db_obj
