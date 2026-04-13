from sqlalchemy.orm import Session
from . import models, schemas

class ThreatService:
    @staticmethod
    def get_cve(db: Session, cve_id: str):
        return db.query(models.CVE).filter(models.CVE.cve_id == cve_id).first()

    @staticmethod
    def list_cves(db: Session, skip: int = 0, limit: int = 100):
        return db.query(models.CVE).offset(skip).limit(limit).all()

    @staticmethod
    def create_cve(db: Session, cve: schemas.CVECreate):
        db_obj = models.CVE(**cve.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    @staticmethod
    def create_exploit(db: Session, exploit):
        db_obj = models.Exploit(**exploit.dict())
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

    @staticmethod
    def list_exploits(db: Session, skip: int = 0, limit: int = 100):
        return db.query(models.Exploit).offset(skip).limit(limit).all()

