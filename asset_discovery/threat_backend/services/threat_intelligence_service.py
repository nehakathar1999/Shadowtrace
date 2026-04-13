"""
Threat Intelligence Service — orchestrates all collectors and provides
data access methods for routers.
"""
from datetime import datetime, timedelta
from typing import Optional, List
from loguru import logger
from sqlalchemy import select, func

from threat_backend.database import AsyncSessionLocal
from threat_backend.config import settings
from threat_backend.services.cve_collector import CVECollector
from threat_backend.models.orm_models import FeedLog, FeedStatus, FeedConfig, CVE, Exploit, ThreatCorrelation

class ThreatIntelligenceService:

    def __init__(self):
        self.cve_collector = CVECollector()
        # TODO: migrate ExploitCollector, MITREAttackCollector, CorrelationEngine to SQLAlchemy

    # ─── Feed Update Orchestration ───────────────────────────────────────

    async def run_full_update(self, triggered_by: str = "scheduler") -> dict:
        """Run all feed updates and correlation pass."""
        logger.info(f"ThreatIntel: Full update started (triggered by: {triggered_by})")
        results = {}

        # 1. CVE Feed
        results["cve"] = await self._run_feed("cve", self._update_cve_feed)

        # 2. ExploitDB
        results["exploitdb"] = await self._run_feed("exploitdb", self._update_exploit_feed)

        # 3. MITRE ATT&CK
        results["mitre"] = await self._run_feed("mitre", self._update_mitre_feed)

        # 4. Correlation Engine
        results["correlation"] = await self._run_feed("correlation", self._run_correlation)

        # 5. Data Retention Cleanup
        await self.cleanup_old_data()

        logger.info(f"ThreatIntel: Full update complete. Results: {results}")
        return results

    async def run_cve_update(self) -> dict:
        return await self._run_feed("cve", self._update_cve_feed)

    async def run_exploit_update(self) -> dict:
        return await self._run_feed("exploitdb", self._update_exploit_feed)

    async def run_mitre_update(self) -> dict:
        return await self._run_feed("mitre", self._update_mitre_feed)

    async def run_correlation_update(self) -> dict:
        return await self._run_feed("correlation", self._run_correlation)

    async def _run_feed(self, feed_type: str, func) -> dict:
        async with AsyncSessionLocal() as session:
            start = datetime.utcnow()

            # Mark as running
            stmt = select(FeedStatus).where(FeedStatus.feed_name == feed_type)
            result = await session.execute(stmt)
            feed_status = result.scalar_one_or_none()
            
            if feed_status:
                feed_status.status = "running"
                feed_status.last_run = start
            else:
                feed_status = FeedStatus(feed_name=feed_type, status="running", last_run=start)
                session.add(feed_status)
            
            await session.commit()

            try:
                result = await func()
                duration = (datetime.utcnow() - start).total_seconds()
                records = result if isinstance(result, int) else result.get("total", 0)

                # Insert feed log
                log = FeedLog(
                    feed_type=feed_type,
                    status="success",
                    records_fetched=records,
                    duration_seconds=duration,
                )
                session.add(log)

                # Update feed status
                feed_status.status = "success"
                feed_status.records_fetched = records
                feed_status.error_message = None
                
                await session.commit()
                return {"status": "success", "records": records, "duration_s": duration}

            except Exception as e:
                duration = (datetime.utcnow() - start).total_seconds()
                logger.error(f"Feed {feed_type} failed: {e}")
                
                # Insert error log
                log = FeedLog(
                    feed_type=feed_type,
                    status="failed",
                    error_message=str(e)[:500],
                    duration_seconds=duration,
                )
                session.add(log)

                # Update feed status
                feed_status.status = "failed"
                feed_status.error_message = str(e)[:500]
                
                await session.commit()
                return {"status": "failed", "error": str(e)[:200]}

    async def _update_cve_feed(self) -> int:
        return await self.cve_collector.fetch_recent_cves(days_back=settings.DATA_RETENTION_DAYS)

    async def _update_exploit_feed(self) -> int:
        logger.warning("ExploitCollector not yet migrated to SQLAlchemy - skipping")
        return 0

    async def _update_mitre_feed(self):
        logger.warning("MITREAttackCollector not yet migrated to SQLAlchemy - skipping")
        return {"techniques": 0}

    async def _run_correlation(self) -> int:
        logger.warning("CorrelationEngine not yet migrated to SQLAlchemy - skipping")
        return 0

    # ─── Data Retention ──────────────────────────────────────────────────

    async def cleanup_old_data(self):
        """Remove CVEs and feed logs older than DATA_RETENTION_DAYS."""
        async with AsyncSessionLocal() as session:
            cutoff = datetime.utcnow() - timedelta(days=settings.DATA_RETENTION_DAYS)

            # Clean old feed logs
            stmt = select(FeedLog).where(FeedLog.timestamp < cutoff)
            result = await session.execute(stmt)
            old_logs = result.scalars().all()
            for log in old_logs:
                await session.delete(log)
            logger.info(f"Retention cleanup: deleted {len(old_logs)} old feed logs")

            # Clean old CVEs (by published date)
            stmt = select(CVE).where(CVE.published_date < cutoff)
            result = await session.execute(stmt)
            old_cves = result.scalars().all()
            for cve in old_cves:
                await session.delete(cve)
            logger.info(f"Retention cleanup: deleted {len(old_cves)} old CVEs")

            # Clean old correlations
            stmt = select(ThreatCorrelation).where(ThreatCorrelation.correlation_timestamp < cutoff)
            result = await session.execute(stmt)
            old_corr = result.scalars().all()
            for corr in old_corr:
                await session.delete(corr)
            
            await session.commit()

    async def get_dashboard_stats(self):
        """Get dashboard statistics from database."""
        async with AsyncSessionLocal() as session:
            # Counts using SQLAlchemy
            total_cves = await session.scalar(select(func.count()).select_from(CVE)) or 0
            critical = await session.scalar(
                select(func.count()).select_from(CVE).where(CVE.severity == "CRITICAL")
            ) or 0
            high = await session.scalar(
                select(func.count()).select_from(CVE).where(CVE.severity == "HIGH")
            ) or 0
            medium = await session.scalar(
                select(func.count()).select_from(CVE).where(CVE.severity == "MEDIUM")
            ) or 0
            low = await session.scalar(
                select(func.count()).select_from(CVE).where(CVE.severity.in_(["LOW", "NONE"]))
            ) or 0
            
            exploits = await session.scalar(select(func.count()).select_from(Exploit)) or 0
            verified = await session.scalar(
                select(func.count()).select_from(Exploit).where(Exploit.verified == True)
            ) or 0
            
            correlations = await session.scalar(select(func.count()).select_from(ThreatCorrelation)) or 0
            critical_corr = await session.scalar(
                select(func.count()).select_from(ThreatCorrelation).where(ThreatCorrelation.risk_level == "CRITICAL")
            ) or 0
            high_corr = await session.scalar(
                select(func.count()).select_from(ThreatCorrelation).where(ThreatCorrelation.risk_level == "HIGH")
            ) or 0

            # Feed statuses
            stmt = select(FeedStatus)
            result = await session.execute(stmt)
            feed_statuses = result.scalars().all()

            return {
                "total_cves": total_cves,
                "critical_cves": critical,
                "high_cves": high,
                "medium_cves": medium,
                "low_cves": low,
                "total_exploits": exploits,
                "verified_exploits": verified,
                "total_correlations": correlations,
                "critical_correlations": critical_corr,
                "high_risk_correlations": high_corr,
                "feed_statuses": feed_statuses,
                "last_updated": datetime.utcnow(),
            }

    # ─── Feed Schedule Config ─────────────────────────────────────────────

    async def get_feed_config(self) -> dict:
        """Get current feed configuration."""
        async with AsyncSessionLocal() as session:
            stmt = select(FeedConfig).limit(1)
            result = await session.execute(stmt)
            config_obj = result.scalar_one_or_none()
            
            if config_obj:
                return {
                    "schedule_type": config_obj.schedule_type,
                    "enabled": config_obj.enabled,
                    "updated_at": config_obj.updated_at,
                }
            else:
                return {"schedule_type": "daily", "enabled": True}

    async def set_feed_config(self, schedule_type: str, enabled: bool) -> dict:
        """Update feed configuration."""
        async with AsyncSessionLocal() as session:
            stmt = select(FeedConfig).limit(1)
            result = await session.execute(stmt)
            config_obj = result.scalar_one_or_none()
            
            if config_obj:
                config_obj.schedule_type = schedule_type
                config_obj.enabled = enabled
                config_obj.updated_at = datetime.utcnow()
            else:
                config_obj = FeedConfig(
                    schedule_type=schedule_type,
                    enabled=enabled,
                    updated_at=datetime.utcnow()
                )
                session.add(config_obj)
            
            await session.commit()
            
            return {
                "schedule_type": config_obj.schedule_type,
                "enabled": config_obj.enabled,
                "updated_at": config_obj.updated_at,
            }

