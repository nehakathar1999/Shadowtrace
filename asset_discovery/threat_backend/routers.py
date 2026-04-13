from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from . import services, schemas, models

router = APIRouter(prefix="/api/threat", tags=["Threat Intelligence"])

# authority to create tables from models
models.Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/cves", response_model=list[schemas.CVEOut])
def read_cves(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    return services.ThreatService.list_cves(db, skip=skip, limit=limit)


@router.post("/cves", response_model=schemas.CVEOut)
def create_cve(cve: schemas.CVECreate, db: Session = Depends(get_db)):
    existing = services.ThreatService.get_cve(db, cve.cve_id)
    if existing:
        raise HTTPException(status_code=400, detail=f"CVE {cve.cve_id} already exists")
    return services.ThreatService.create_cve(db, cve)


@router.get("/cves/{cve_id}", response_model=schemas.CVEOut)
def read_cve(cve_id: str, db: Session = Depends(get_db)):
    db_obj = services.ThreatService.get_cve(db, cve_id)
    if not db_obj:
        raise HTTPException(status_code=404, detail="CVE not found")
    return db_obj


@router.get("/exploits", response_model=list[schemas.ExploitOut])
def read_exploits(skip: int = 0, limit: int = 50, db: Session = Depends(get_db)):
    return services.ThreatService.list_exploits(db, skip=skip, limit=limit)


@router.post("/exploits", response_model=schemas.ExploitOut)
def create_exploit(exploit: schemas.ExploitBase, db: Session = Depends(get_db)):
    return services.ThreatService.create_exploit(db, exploit)

