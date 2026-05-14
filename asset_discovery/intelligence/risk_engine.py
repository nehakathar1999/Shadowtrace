def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def prioritize_asset_vulnerabilities(asset: dict) -> dict:
    prioritized = []
    for vulnerability in asset.get("vulnerabilities", []) or []:
        cvss = float(vulnerability.get("cvss_score") or 0)
        score = min(100, round(cvss * 10))
        updated = dict(vulnerability)
        updated.update({
            "asset_importance": None,
            "asset_importance_score": None,
            "exploit_available": bool(vulnerability.get("exploit_available")),
            "risk_score": score,
            "risk_severity": _severity_from_score(score),
            "risk_formula": f"CVSS-based risk score: {cvss} x 10 = {score}",
        })
        prioritized.append(updated)

    prioritized.sort(key=lambda item: item.get("risk_score", 0), reverse=True)
    asset_summary = {
        "asset_importance": None,
        "asset_importance_score": None,
        "highest_risk_score": prioritized[0]["risk_score"] if prioritized else 0,
    }
    return {"vulnerabilities": prioritized, "summary": asset_summary}
