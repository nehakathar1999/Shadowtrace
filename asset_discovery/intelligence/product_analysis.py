from __future__ import annotations

from typing import Any


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.get(str(severity or "").upper(), -1)


def confidence_label(score: int) -> str:
    if score >= 90:
        return "confirmed"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def validation_state(version_present: bool, direct_proof: bool) -> str:
    if direct_proof:
        return "confirmed"
    if version_present:
        return "validated_version"
    return "hypothesis"


def compliance_mapping(service: str | None, title: str | None, severity: str | None = None) -> list[str]:
    service_name = str(service or "").lower()
    finding_title = str(title or "").lower()
    mappings = {"OWASP Top 10", "ISO 27001 A.8.8", "ISO 27001 A.8.9"}

    if any(token in finding_title for token in ("auth", "login", "credential", "access control", "idor")):
        mappings.update({"OWASP A01 Broken Access Control", "PCI DSS 7.2", "PCI DSS 8.2"})
    if any(token in finding_title for token in ("sql", "xss", "injection", "template injection")):
        mappings.update({"OWASP A05 Injection", "PCI DSS 6.2.4"})
    if any(token in finding_title for token in ("tls", "cipher", "https", "cookie", "crypto")):
        mappings.update({"OWASP A04 Cryptographic Failures", "PCI DSS 4.2.1"})
    if any(token in finding_title for token in ("header", "misconfiguration", "debug", "backup", "server fingerprint")):
        mappings.update({"OWASP A02 Security Misconfiguration", "PCI DSS 2.2.1"})
    if service_name in {"ssh", "rdp", "smb", "ftp", "mysql", "postgresql", "redis"}:
        mappings.add("CIS Control 12")
    if str(severity or "").upper() == "CRITICAL":
        mappings.add("ISO 27001 A.5.7")

    return sorted(mappings)


def business_impact(service: str | None, severity: str | None, title: str | None = None) -> str:
    service_name = str(service or "").lower()
    severity_name = str(severity or "").upper()
    title_text = str(title or "").lower()

    if any(token in title_text for token in ("rce", "remote code", "eternalblue", "bluekeep")) or severity_name == "CRITICAL":
        return "Potential full host compromise, lateral movement, and service disruption."
    if service_name in {"http", "https"} and any(token in title_text for token in ("access", "idor", "backup", "auth")):
        return "Possible unauthorized access to application data, admin functions, or user records."
    if service_name in {"mysql", "postgresql", "redis"}:
        return "Possible database exposure, credential abuse, or loss of data confidentiality and integrity."
    if service_name in {"ssh", "rdp", "smb"}:
        return "Could allow privileged access paths into internal systems and support lateral movement."
    if severity_name == "HIGH":
        return "Likely to expose sensitive data or significantly weaken perimeter defenses."
    if severity_name == "MEDIUM":
        return "Increases exploitable attack surface and may become dangerous when chained with other weaknesses."
    return "Creates avoidable exposure and should be addressed as part of normal hardening."


def remediation_plan(service: str | None, product: str | None, version: str | None, title: str | None = None) -> str:
    service_name = str(service or "").lower()
    product_name = str(product or service or "the affected service").strip()
    version_text = str(version or "").strip()
    title_text = str(title or "").lower()

    upgrade_line = (
        f"Upgrade {product_name} from {version_text} to the latest vendor-supported fixed release."
        if version_text
        else f"Confirm the deployed {product_name} version and upgrade to the latest vendor-supported fixed release."
    )

    exact_steps = {
        "http": "Review public routes, disable unnecessary endpoints, remove debug files, and set strict response headers such as Content-Security-Policy, X-Frame-Options, and X-Content-Type-Options.",
        "https": "Disable weak TLS versions and ciphers, enforce TLS 1.2+ or TLS 1.3, and add Strict-Transport-Security for internet-facing applications.",
        "ssh": "Restrict SSH to management networks, disable password authentication where possible, and enforce key-based logins plus MFA on jump hosts.",
        "ftp": "Disable FTP if it is not required; otherwise move to SFTP/FTPS and restrict access to trusted administration networks only.",
        "smb": "Disable SMBv1, apply current Microsoft patches, and block SMB exposure from untrusted networks.",
        "rdp": "Require Network Level Authentication, restrict RDP behind VPN or a bastion host, and apply current Windows security updates.",
        "mysql": "Bind the database to internal interfaces only, remove anonymous access, rotate exposed credentials, and restrict application accounts to least privilege.",
        "postgresql": "Restrict PostgreSQL to internal interfaces, enforce strong authentication, and review search_path, trust authentication, and role privileges.",
        "redis": "Bind Redis to localhost or internal interfaces, set authentication, disable dangerous commands, and avoid public exposure entirely.",
        "vnc": "Require strong authentication, place VNC behind VPN access, and disable any unauthenticated or legacy remote-control modes.",
    }
    detail = exact_steps.get(service_name, "Restrict the service to trusted networks only, remove it if unnecessary, and validate the fix with a follow-up scan.")

    if "content-security-policy" in title_text or "header" in title_text:
        detail = "Set explicit security headers. Example: Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none'."
    elif "cookie" in title_text:
        detail = "Issue session cookies with Secure, HttpOnly, and SameSite=Lax or SameSite=Strict, and rotate active sessions after changing cookie policy."
    elif "sql injection" in title_text:
        detail = "Replace string-built queries with parameterized queries, validate input types at the boundary, and add server-side error handling that does not leak SQL parser output."
    elif "xss" in title_text:
        detail = "Encode untrusted output by context, validate and sanitize user-controlled fields, and backstop browser defenses with a strict Content-Security-Policy."

    return f"{upgrade_line} {detail}"


def make_evidence(
    *,
    observed: list[str] | None = None,
    request: dict[str, Any] | None = None,
    response: dict[str, Any] | None = None,
    payload: str | None = None,
    conclusion: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "observed": observed or [],
        "request": request,
        "response": response,
        "payload": payload,
        "conclusion": conclusion,
    }
    return {key: value for key, value in data.items() if value not in (None, [], "", {})}


def enrich_finding(
    finding: dict[str, Any],
    *,
    validation: str,
    confidence_score: int,
    evidence: dict[str, Any] | None = None,
    source: str,
) -> dict[str, Any]:
    service = finding.get("service")
    title = finding.get("title")
    severity = finding.get("severity")
    product = finding.get("product")
    version = finding.get("version")

    enriched = dict(finding)
    enriched["validation_state"] = validation
    enriched["confidence_score"] = confidence_score
    enriched["confidence"] = confidence_label(confidence_score)
    enriched["source"] = source
    enriched["business_impact"] = finding.get("business_impact") or business_impact(service, severity, title)
    enriched["remediation"] = finding.get("remediation") or remediation_plan(service, product, version, title)
    enriched["compliance_mapping"] = finding.get("compliance_mapping") or compliance_mapping(service, title, severity)
    enriched["proof"] = evidence or finding.get("proof") or {}
    enriched["remediation_type"] = "actionable"
    return enriched


def build_top_risks(vulnerabilities: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    ordered = sorted(
        vulnerabilities,
        key=lambda item: (
            severity_rank(item.get("severity")),
            float(item.get("cvss_score") or 0),
            int(item.get("confidence_score") or 0),
        ),
        reverse=True,
    )
    top = []
    for item in ordered[:limit]:
        top.append({
            "title": item.get("title"),
            "severity": item.get("severity"),
            "asset": item.get("host") or item.get("hostname") or item.get("ip"),
            "service": item.get("service"),
            "port": item.get("port"),
            "confidence": item.get("confidence"),
            "confidence_score": item.get("confidence_score"),
            "validation_state": item.get("validation_state"),
            "business_impact": item.get("business_impact"),
            "fix_now": item.get("remediation"),
        })
    return top


def build_attack_paths(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths = []
    for asset in assets:
        vulns = asset.get("vulnerabilities", []) or []
        host_label = asset.get("domain") or asset.get("hostname") or asset.get("ip")
        admin_exposure = next((v for v in vulns if "admin" in str(v.get("title", "")).lower() or "access" in str(v.get("title", "")).lower()), None)
        credential_or_backup = next((v for v in vulns if any(token in str(v.get("title", "")).lower() for token in ("backup", "credential", "default credentials", "auth"))), None)
        remote_admin = next((v for v in vulns if str(v.get("service", "")).lower() in {"ssh", "rdp", "smb"}), None)
        if admin_exposure and credential_or_backup and remote_admin:
            paths.append({
                "title": f"Likely compromise chain for {host_label}",
                "risk": "CRITICAL",
                "summary": "An attacker could abuse weak access controls to collect secrets and pivot into remote administration services.",
                "steps": [
                    f"Reach exposed functionality: {admin_exposure.get('title')}",
                    f"Extract or abuse sensitive access data: {credential_or_backup.get('title')}",
                    f"Pivot using remote administration service on port {remote_admin.get('port')}: {remote_admin.get('title')}",
                ],
            })
            continue

        internet_exposed = [v for v in vulns if str(v.get("severity", "")).upper() in {"CRITICAL", "HIGH"}]
        if len(internet_exposed) >= 2:
            paths.append({
                "title": f"Multi-step attack path for {host_label}",
                "risk": internet_exposed[0].get("severity", "HIGH"),
                "summary": "Multiple high-impact issues on the same asset could be chained to deepen access or increase blast radius.",
                "steps": [
                    f"Initial foothold: {internet_exposed[0].get('title')}",
                    f"Post-access leverage: {internet_exposed[1].get('title')}",
                ],
            })
    return paths[:5]


def executive_summary(payload: dict[str, Any]) -> dict[str, Any]:
    assets = payload.get("assets", []) or []
    vulnerabilities = []
    for asset in assets:
        host = asset.get("domain") or asset.get("hostname") or asset.get("ip")
        for item in asset.get("vulnerabilities", []) or []:
            merged = dict(item)
            merged["host"] = host
            merged["ip"] = asset.get("resolved_ip") or asset.get("ip")
            vulnerabilities.append(merged)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    confirmed = 0
    hypotheses = 0
    for item in vulnerabilities:
        sev = str(item.get("severity") or "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        if item.get("validation_state") == "confirmed":
            confirmed += 1
        elif item.get("validation_state") == "hypothesis":
            hypotheses += 1

    top_risks = build_top_risks(vulnerabilities)
    attack_paths = build_attack_paths(assets)

    narrative = (
        f"The scan identified {len(vulnerabilities)} infrastructure finding(s) across {len(assets)} active host(s). "
        f"{confirmed} finding(s) are confirmed with direct proof, while {hypotheses} remain hypotheses that need manual validation."
    )
    if top_risks:
        narrative += f" Immediate attention should focus on {top_risks[0].get('title')}."

    return {
        "narrative": narrative,
        "severity_breakdown": severity_counts,
        "confirmed_findings": confirmed,
        "needs_validation": hypotheses,
        "top_risks": top_risks,
        "attack_paths": attack_paths,
    }
