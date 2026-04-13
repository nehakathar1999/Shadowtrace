import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from threat_backend.database import get_db
from threat_backend.models.orm_models import CVE
from threat_backend.services.catalog_service import ThreatCatalogService

router = APIRouter(prefix="/api/threat-intel", tags=["Threat Intelligence"])
logger = logging.getLogger(__name__)


def _serialize_cve(item: CVE) -> dict:
    return {
        "cve_id": item.cve_id,
        "description": item.description,
        "published_date": item.published_date.isoformat() if item.published_date else None,
        "last_modified": item.last_modified.isoformat() if item.last_modified else None,
        "cvss_score": item.cvss_score,
        "severity": item.severity,
        "cwe_ids": item.cwe_ids or [],
        "affected_products": item.affected_products or [],
        "references": item.references or [],
        "_source": "local_db",
    }


@router.get("/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    return ThreatCatalogService.get_dashboard(db)


@router.get("/cves")
def list_cves(
    severity: str | None = None,
    min_cvss: float | None = None,
    keyword: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    try:
        total, items = ThreatCatalogService.list_cves(
            db,
            severity=severity,
            min_cvss=min_cvss,
            keyword=keyword,
            page=page,
            page_size=page_size,
        )
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "data": [_serialize_cve(item) for item in items],
        }
    except Exception:
        logger.exception("Failed to list CVEs from threat intelligence catalog")
        return {
            "total": 0,
            "page": page,
            "page_size": page_size,
            "data": [],
        }


@router.get("/cves/{cve_id}")
def get_cve(cve_id: str, db: Session = Depends(get_db)):
    item = ThreatCatalogService.get_cve(db, cve_id)
    if not item:
        raise HTTPException(status_code=404, detail="CVE not found")
    return {"cve": _serialize_cve(item), "correlation": None}


@router.get("/exploits")
def list_exploits(
    platform: str | None = None,
    keyword: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    total, items = ThreatCatalogService.list_exploits(
        db,
        platform=platform,
        keyword=keyword,
        page=page,
        page_size=page_size,
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "data": [
            {
                "exploit_id": item.exploit_id,
                "title": item.title,
                "description": item.description,
                "platform": item.platform,
                "date": item.date.isoformat() if item.date else None,
                "url": item.url,
            }
            for item in items
        ],
    }
