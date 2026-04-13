"""
FR-07 — Threat Correlation Engine
Correlates CVE data with exploit availability, MITRE ATT&CK techniques,
and calculates composite risk scores for each vulnerability.
"""
from datetime import datetime
from typing import List, Optional
from loguru import logger
import uuid

from threat_backend.database import get_db
from threat_backend.models.correlation_model import CorrelationModel

# ─── Risk Scoring Weights ────────────────────────────────────────────────────
WEIGHTS = {
    "cvss_score":            0.35,
    "exploit_availability":  0.30,
    "asset_criticality":     0.20,
    "threat_intel_activity": 0.15,
}

CVSS_SEVERITY_MAP = {
    "NONE":     (0.0, 3.9),
    "LOW":      (0.1, 3.9),
    "MEDIUM":   (4.0, 6.9),
    "HIGH":     (7.0, 8.9),
    "CRITICAL": (9.0, 10.0),
}

CRITICALITY_SCORE = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}

class CorrelationEngine:

    async def run_full_correlation(self) -> int:
        """
        Full correlation pass — runs after each feed update cycle.
        Correlates ALL CVEs in DB with exploits and MITRE techniques.
        """
        db = get_db()
        logger.info("Correlation Engine: Starting full correlation pass...")

        # Load all exploit CVE mappings into memory for fast lookup
        exploit_map = {}  # cve_id -> List[exploit_id]
        exploit_verified_map = {}  # cve_id -> bool
        async for exp in db.exploits.find({}, {"exploit_id": 1, "cve_ids": 1, "verified": 1}):
            for cid in exp.get("cve_ids", []):
                if cid not in exploit_map:
                    exploit_map[cid] = []
                    exploit_verified_map[cid] = False
                exploit_map[cid].append(exp["exploit_id"])
                if exp.get("verified"):
                    exploit_verified_map[cid] = True

        # Load MITRE technique CVE mappings (if any have been linked)
        # Also map CWE IDs to ATT&CK techniques (heuristic)
        cwe_to_technique = await self._build_cwe_technique_map(db)

        count = 0
        async for cve in db.cves.find({}):
            cve_id = cve.get("cve_id", "")
            if not cve_id:
                continue

            exploit_ids = exploit_map.get(cve_id, [])
            exploit_verified = exploit_verified_map.get(cve_id, False)

            # MITRE linkage via CWE
            cwe_ids = cve.get("cwe_ids", [])
            technique_ids = []
            technique_names = []
            tactic_names = []
            for cwe in cwe_ids:
                techs = cwe_to_technique.get(cwe, [])
                for t in techs:
                    if t["id"] not in technique_ids:
                        technique_ids.append(t["id"])
                        technique_names.append(t["name"])
                        for tn in t.get("tactic_names", []):
                            if tn not in tactic_names:
                                tactic_names.append(tn)

            # Risk score
            cvss_score = cve.get("cvss_score", 0.0)
            risk_score, risk_level, exploit_prob = self._calculate_risk(
                cvss_score=cvss_score,
                has_exploit=len(exploit_ids) > 0,
                exploit_verified=exploit_verified,
                has_mitre_link=len(technique_ids) > 0,
                exploit_count=len(exploit_ids),
            )

            correlation = CorrelationModel(
                correlation_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, cve_id)),
                cve_id=cve_id,
                cve_description=cve.get("description", "")[:300],
                cvss_score=cvss_score,
                severity=cve.get("severity", "NONE"),
                exploit_count=len(exploit_ids),
                exploit_ids=exploit_ids[:10],
                exploit_verified=exploit_verified,
                mitre_technique_ids=technique_ids[:5],
                mitre_technique_names=technique_names[:5],
                mitre_tactic_names=tactic_names[:5],
                risk_score=risk_score,
                risk_level=risk_level,
                exploit_probability=exploit_prob,
                correlation_timestamp=datetime.utcnow(),
            )

            await db.threat_correlations.update_one(
                {"cve_id": cve_id},
                {"$set": correlation.model_dump()},
                upsert=True,
            )
            count += 1

        logger.info(f"Correlation Engine: Correlated {count} CVEs")
        return count

    async def correlate_vulnerability(self, vuln_doc: dict) -> dict:
        """
        Enrich a single vulnerability document (from other team's scanner)
        with threat intelligence context.
        """
        db = get_db()
        cve_id = vuln_doc.get("cve_id")
        if not cve_id:
            return vuln_doc

        # Look up existing correlation
        corr = await db.threat_correlations.find_one({"cve_id": cve_id})
        if corr:
            vuln_doc["risk_score"] = corr.get("risk_score", 0.0)
            vuln_doc["risk_level"] = corr.get("risk_level", "LOW")
            vuln_doc["exploit_available"] = corr.get("exploit_count", 0) > 0
            vuln_doc["exploit_count"] = corr.get("exploit_count", 0)
            vuln_doc["mitre_techniques"] = corr.get("mitre_technique_names", [])
            vuln_doc["exploit_probability"] = corr.get("exploit_probability", 0.0)

        return vuln_doc

    def _calculate_risk(
        self,
        cvss_score: float,
        has_exploit: bool,
        exploit_verified: bool,
        has_mitre_link: bool,
        exploit_count: int,
        asset_criticality: str = "medium",
    ) -> tuple:
        """
        Composite Risk Score Formula:
        Score = (cvss_normalized × 0.35) + (exploit_score × 0.30)
              + (asset_score × 0.20) + (intel_score × 0.15)
        Returns (risk_score_0_100, risk_level, exploit_probability)
        """
        # Normalize CVSS to 0–1
        cvss_normalized = min(cvss_score / 10.0, 1.0)

        # Exploit score
        if not has_exploit:
            exploit_score = 0.0
        elif exploit_verified:
            exploit_score = 1.0
        elif exploit_count > 3:
            exploit_score = 0.85
        else:
            exploit_score = 0.6

        # Asset criticality score
        asset_score = CRITICALITY_SCORE.get(asset_criticality, 0.5)

        # Threat intel score (MITRE linkage)
        intel_score = 0.7 if has_mitre_link else 0.3

        raw = (
            cvss_normalized * WEIGHTS["cvss_score"]
            + exploit_score * WEIGHTS["exploit_availability"]
            + asset_score * WEIGHTS["asset_criticality"]
            + intel_score * WEIGHTS["threat_intel_activity"]
        )

        risk_score = round(raw * 100, 2)

        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Exploit probability heuristic
        exploit_prob = round(min(exploit_score * 0.85 + cvss_normalized * 0.15, 1.0), 3)

        return risk_score, risk_level, exploit_prob

    async def _build_cwe_technique_map(self, db) -> dict:
        """
        Build a lookup of CWE-ID → MITRE techniques.
        Uses keyword matching on technique descriptions to link CWEs.
        This is a heuristic approach; a full mapping would use CAPEC.
        """
        # Static heuristic map (CWE → ATT&CK technique IDs)
        STATIC_MAP = {
            "CWE-78":  ["T1059"],   # OS Command Injection → Command and Scripting Interpreter
            "CWE-79":  ["T1059.007"],  # XSS → JavaScript
            "CWE-89":  ["T1190"],   # SQL Injection → Exploit Public-Facing Application
            "CWE-190": ["T1499"],   # Integer Overflow → Endpoint Denial of Service
            "CWE-22":  ["T1083"],   # Path Traversal → File and Directory Discovery
            "CWE-306": ["T1078"],   # Missing Authentication → Valid Accounts
            "CWE-502": ["T1059"],   # Deserialization → Command and Scripting Interpreter
            "CWE-119": ["T1203"],   # Buffer Overflow → Exploitation for Client Execution
            "CWE-416": ["T1203"],   # Use After Free
            "CWE-434": ["T1105"],   # Unrestricted Upload → Ingress Tool Transfer
            "CWE-287": ["T1078"],   # Improper Auth → Valid Accounts
            "CWE-798": ["T1078.001"],  # Hardcoded Credentials
            "CWE-200": ["T1213"],   # Info Exposure → Data from Information Repositories
            "CWE-918": ["T1090"],   # SSRF → Proxy
            "CWE-611": ["T1059"],   # XXE
        }

        # Build map with technique names from DB
        result = {}
        for cwe, tech_ids in STATIC_MAP.items():
            techs = []
            for tid in tech_ids:
                tech_doc = await db.mitre_techniques.find_one({"technique_id": tid}, {"technique_id": 1, "name": 1, "tactic_names": 1})
                if tech_doc:
                    techs.append({
                        "id": tech_doc["technique_id"],
                        "name": tech_doc["name"],
                        "tactic_names": tech_doc.get("tactic_names", []),
                    })
            if techs:
                result[cwe] = techs

        return result

