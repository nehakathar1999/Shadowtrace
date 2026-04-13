import httpx
import asyncio
from datetime import datetime, timedelta
from typing import Optional
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from threat_backend.config import settings
from threat_backend.database import AsyncSessionLocal
from threat_backend.models.orm_models import CVE

class CVECollector:
    """
    Fetches CVE data from NIST NVD (National Vulnerability Database).
    Public API — no key required (key raises rate limits from 5 req/30s to 50 req/30s).
    Docs: https://nvd.nist.gov/developers/vulnerabilities
    """

    BASE_URL = settings.NVD_BASE_URL
    RESULTS_PER_PAGE = 2000

    def __init__(self):
        self.headers = {"User-Agent": "AVAVM-ThreatIntel/1.0"}
        if settings.NVD_API_KEY:
            self.headers["apiKey"] = settings.NVD_API_KEY

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=30))
    async def _fetch_page(self, client: httpx.AsyncClient, params: dict) -> dict:
        response = await client.get(self.BASE_URL, params=params, headers=self.headers, timeout=60)
        response.raise_for_status()
        return response.json()

    async def fetch_recent_cves(self, days_back: int = 30) -> int:
        """Fetch CVEs published in the last N days."""
        async with AsyncSessionLocal() as session:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)

            pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
            pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.999")

            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": self.RESULTS_PER_PAGE,
                "startIndex": 0,
            }

            total_fetched = 0

            async with httpx.AsyncClient() as client:
                while True:
                    try:
                        data = await self._fetch_page(client, params)
                        vulnerabilities = data.get("vulnerabilities", [])

                        if not vulnerabilities:
                            break

                        for item in vulnerabilities:
                            cve_dict = self._parse_nvd_item(item)
                            if cve_dict:
                                await self._upsert_cve(session, cve_dict)
                                total_fetched += 1

                        total_results = data.get("totalResults", 0)
                        start_index = params["startIndex"] + len(vulnerabilities)

                        if start_index >= total_results:
                            break

                        params["startIndex"] = start_index
                        # Respect NVD rate limits
                        await asyncio.sleep(0.6 if settings.NVD_API_KEY else 6)

                    except Exception as e:
                        logger.error(f"CVE fetch error at index {params['startIndex']}: {e}")
                        break

        logger.info(f"CVE Collector: fetched/updated {total_fetched} CVEs")
        return total_fetched

    async def fetch_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """Fetch a single CVE by ID from NVD."""
        async with httpx.AsyncClient() as client:
            params = {"cveId": cve_id}
            data = await self._fetch_page(client, params)
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._parse_nvd_item(vulns[0])
        return None

    def _parse_nvd_item(self, item: dict) -> Optional[dict]:
        try:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                return None

            # Description
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            # Dates
            published = self._parse_date(cve_data.get("published"))
            modified = self._parse_date(cve_data.get("lastModified"))

            # CVSS Metrics
            cvss_v3 = None
            cvss_v2 = None
            cvss_score = 0.0
            severity = "NONE"

            metrics = cve_data.get("metrics", {})

            # Try CVSSv3.1 first, then 3.0
            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0].get("cvssData", {})
                    cvss_v3 = {
                        "version": m.get("version", "3.1"),
                        "vector_string": m.get("vectorString"),
                        "base_score": m.get("baseScore", 0.0),
                        "base_severity": m.get("baseSeverity", "NONE"),
                        "exploitability_score": metrics[key][0].get("exploitabilityScore"),
                        "impact_score": metrics[key][0].get("impactScore"),
                    }
                    cvss_score = cvss_v3["base_score"]
                    severity = cvss_v3["base_severity"]
                    break

            if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                m = metrics["cvssMetricV2"][0].get("cvssData", {})
                cvss_v2 = {
                    "version": "2.0",
                    "vector_string": m.get("vectorString"),
                    "base_score": m.get("baseScore", 0.0),
                    "base_severity": metrics["cvssMetricV2"][0].get("baseSeverity", "NONE"),
                }
                if cvss_score == 0.0:
                    cvss_score = cvss_v2["base_score"]
                    severity = cvss_v2["base_severity"]

            # CWE
            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                        cwe_ids.append(desc["value"])

            # Affected Products
            affected_products = []
            configs = cve_data.get("configurations", [])
            for config in configs[:5]:
                for node in config.get("nodes", [])[:5]:
                    for cpe_match in node.get("cpeMatch", [])[:3]:
                        cpe_uri = cpe_match.get("criteria", "")
                        parts = cpe_uri.split(":")
                        if len(parts) >= 5:
                            affected_products.append({
                                "vendor": parts[3] if parts[3] != "*" else None,
                                "product": parts[4] if parts[4] != "*" else None,
                                "version": parts[5] if len(parts) > 5 and parts[5] != "*" else None,
                                "version_end": cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding"),
                            })

            # References
            refs = []
            for ref in cve_data.get("references", [])[:10]:
                refs.append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source"),
                    "tags": ref.get("tags", []),
                })

            return {
                "cve_id": cve_id,
                "description": description,
                "published_date": published,
                "last_modified": modified,
                "cvss_score": cvss_score,
                "cvss_v3": cvss_v3,
                "cvss_v2": cvss_v2,
                "severity": severity,
                "cwe_ids": cwe_ids,
                "affected_products": affected_products,
                "references": refs,
            }

        except Exception as e:
            logger.warning(f"Error parsing CVE item: {e}")
            return None

    async def _upsert_cve(self, session: AsyncSession, cve_data: dict):
        """Insert or update CVE in database"""
        stmt = select(CVE).where(CVE.cve_id == cve_data["cve_id"])
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update existing
            for key, value in cve_data.items():
                if hasattr(existing, key):
                    setattr(existing, key, value)
            existing.updated_at = datetime.utcnow()
        else:
            # Create new
            new_cve = CVE(**cve_data, created_at=datetime.utcnow())
            session.add(new_cve)
        
        await session.commit()

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None

