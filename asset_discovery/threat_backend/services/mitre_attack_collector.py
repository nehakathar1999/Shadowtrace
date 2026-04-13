import httpx
from datetime import datetime
from typing import Optional, List, Dict
from loguru import logger
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import select

from threat_backend.config import settings
from threat_backend.database import AsyncSessionLocal
from threat_backend.models.orm_models import MITRETactic, MITRETechnique

class MITREAttackCollector:
    """
    Fetches MITRE ATT&CK Enterprise framework data from the official GitHub CTI repo.
    URL: https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    Public, no auth required.
    """

    ATTACK_URL = settings.MITRE_ATTACK_URL

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=2, min=4, max=30))
    async def _fetch_attack_data(self) -> dict:
        async with httpx.AsyncClient(timeout=120) as client:
            logger.info("MITRE ATT&CK: Downloading framework data...")
            response = await client.get(self.ATTACK_URL, headers={"User-Agent": "AVAVM/1.0"})
            response.raise_for_status()
            return response.json()

    async def fetch_attack_data(self) -> dict:
        """Fetch and store all MITRE ATT&CK tactics and techniques."""
        db = get_db()

        try:
            attack_data = await self._fetch_attack_data()
        except Exception as e:
            logger.error(f"MITRE ATT&CK fetch failed: {e}")
            return {"tactics": 0, "techniques": 0}

        objects = attack_data.get("objects", [])

        # Parse tactics
        tactics = {}
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                tactic = self._parse_tactic(obj)
                if tactic:
                    tactics[tactic.short_name] = tactic

        # Parse techniques
        techniques = []
        for obj in objects:
            if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
                tech = self._parse_technique(obj, tactics)
                if tech:
                    techniques.append(tech)

        # Update tactic technique counts
        tactic_tech_count: Dict[str, int] = {}
        for tech in techniques:
            for short_name in tech.tactic_ids:
                tactic_tech_count[short_name] = tactic_tech_count.get(short_name, 0) + 1

        for tactic in tactics.values():
            tactic.technique_count = tactic_tech_count.get(tactic.short_name, 0)

        # Persist
        tactics_saved = await self._upsert_tactics(db, list(tactics.values()))
        techniques_saved = await self._upsert_techniques(db, techniques)

        logger.info(f"MITRE ATT&CK: {tactics_saved} tactics, {techniques_saved} techniques saved")
        return {"tactics": tactics_saved, "techniques": techniques_saved}

    def _parse_tactic(self, obj: dict) -> Optional[MITRETactic]:
        try:
            ext = obj.get("x_mitre_shortname", "")
            name = obj.get("name", "")
            description = obj.get("description", "")
            tactic_id = self._extract_external_id(obj, "mitre-attack") or ext
            return MITRETactic(
                tactic_id=tactic_id,
                name=name,
                short_name=ext,
                description=description[:500] if description else "",
            )
        except Exception as e:
            logger.warning(f"Tactic parse error: {e}")
            return None

    def _parse_technique(self, obj: dict, tactics: Dict[str, MITRETactic]) -> Optional[MITRETechnique]:
        try:
            ext_id = self._extract_external_id(obj, "mitre-attack")
            if not ext_id:
                return None

            name = obj.get("name", "")
            description = obj.get("description", "")[:1000]

            # Kill chain (tactics)
            kill_chain = obj.get("kill_chain_phases", [])
            tactic_short_names = [kc["phase_name"] for kc in kill_chain if kc.get("kill_chain_name") == "mitre-attack"]
            tactic_names = [tactics[sn].name for sn in tactic_short_names if sn in tactics]

            # Subtechnique
            is_sub = "." in ext_id
            parent_id = ext_id.split(".")[0] if is_sub else None

            platforms = obj.get("x_mitre_platforms", [])
            data_sources = obj.get("x_mitre_data_sources", [])
            detection = obj.get("x_mitre_detection", "")[:500]

            url = f"https://attack.mitre.org/techniques/{ext_id.replace('.', '/')}/"

            return MITRETechnique(
                technique_id=ext_id,
                name=name,
                description=description,
                tactic_ids=tactic_short_names,
                tactic_names=tactic_names,
                is_subtechnique=is_sub,
                parent_technique_id=parent_id,
                platforms=platforms,
                data_sources=[ds.split(":")[0].strip() for ds in data_sources[:5]],
                detection=detection,
                url=url,
            )
        except Exception as e:
            logger.warning(f"Technique parse error: {e}")
            return None

    def _extract_external_id(self, obj: dict, source: str) -> Optional[str]:
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == source:
                return ref.get("external_id")
        return None

    async def _upsert_tactics(self, db, tactics: List[MITRETactic]) -> int:
        from pymongo import UpdateOne
        ops = [UpdateOne({"tactic_id": t.tactic_id}, {"$set": t.model_dump()}, upsert=True) for t in tactics]
        if ops:
            result = await db.mitre_tactics.bulk_write(ops, ordered=False)
            return result.upserted_count + result.modified_count
        return 0

    async def _upsert_techniques(self, db, techniques: List[MITRETechnique]) -> int:
        from pymongo import UpdateOne
        BATCH = 500
        total = 0
        for i in range(0, len(techniques), BATCH):
            batch = techniques[i:i + BATCH]
            ops = [UpdateOne({"technique_id": t.technique_id}, {"$set": t.model_dump()}, upsert=True) for t in batch]
            result = await db.mitre_techniques.bulk_write(ops, ordered=False)
            total += result.upserted_count + result.modified_count
        return total

