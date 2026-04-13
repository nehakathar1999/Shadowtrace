from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from threat_backend.models.orm_models import CVE, Exploit, ThreatCorrelation


class ThreatCatalogService:
    @staticmethod
    def list_cves(
        db: Session,
        *,
        severity: str | None = None,
        min_cvss: float | None = None,
        keyword: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[int, list[CVE]]:
        query = db.query(CVE)

        if severity:
            query = query.filter(CVE.severity == severity.upper())
        if min_cvss is not None:
            query = query.filter(CVE.cvss_score >= min_cvss)
        if keyword:
            pattern = f"%{keyword.strip()}%"
            query = query.filter(
                or_(CVE.cve_id.ilike(pattern), CVE.description.ilike(pattern))
            )

        total = query.count()
        items = (
            query.order_by(desc(CVE.cvss_score), desc(CVE.published_date))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        return total, items

    @staticmethod
    def get_cve(db: Session, cve_id: str) -> CVE | None:
        return db.query(CVE).filter(CVE.cve_id == cve_id.upper().strip()).first()

    @staticmethod
    def list_exploits(
        db: Session,
        *,
        platform: str | None = None,
        keyword: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[int, list[Exploit]]:
        query = db.query(Exploit)

        if platform:
            query = query.filter(Exploit.platform.ilike(f"%{platform}%"))
        if keyword:
            pattern = f"%{keyword.strip()}%"
            query = query.filter(
                or_(Exploit.title.ilike(pattern), Exploit.description.ilike(pattern))
            )

        total = query.count()
        items = (
            query.order_by(desc(Exploit.date))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )
        return total, items

    @staticmethod
    def get_dashboard(db: Session) -> dict:
        total_cves = db.query(func.count(CVE.id)).scalar() or 0
        critical_cves = db.query(func.count(CVE.id)).filter(CVE.severity == "CRITICAL").scalar() or 0
        high_cves = db.query(func.count(CVE.id)).filter(CVE.severity == "HIGH").scalar() or 0
        medium_cves = db.query(func.count(CVE.id)).filter(CVE.severity == "MEDIUM").scalar() or 0
        low_cves = db.query(func.count(CVE.id)).filter(CVE.severity.in_(["LOW", "NONE"])).scalar() or 0
        total_exploits = db.query(func.count(Exploit.id)).scalar() or 0
        total_correlations = db.query(func.count(ThreatCorrelation.id)).scalar() or 0

        return {
            "total_cves": total_cves,
            "critical_cves": critical_cves,
            "high_cves": high_cves,
            "medium_cves": medium_cves,
            "low_cves": low_cves,
            "total_exploits": total_exploits,
            "verified_exploits": 0,
            "total_techniques": 0,
            "total_tactics": 0,
            "total_correlations": total_correlations,
            "critical_correlations": 0,
            "high_risk_correlations": 0,
            "cves_with_exploits": 0,
            "feed_statuses": [],
            "last_updated": None,
            "cve_trend": [],
            "severity_distribution": {},
            "top_affected_products": [],
            "top_mitre_tactics": [],
        }
