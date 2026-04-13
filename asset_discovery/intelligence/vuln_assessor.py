import urllib.parse
from config.settings import settings
from intelligence.product_analysis import enrich_finding, make_evidence, remediation_plan

try:
    import requests
except ImportError:
    requests = None


VULN_DB = [
    {
        "cve": "CVE-2023-44487",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.59",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "title": "HTTP/2 Rapid Reset Attack",
        "description": "HTTP/2 protocol vulnerability allowing DDoS-like rapid reset attacks.",
    },
    {
        "cve": "CVE-2016-2107",
        "service": "https",
        "product": "OpenSSL",
        "version": "1.1.1w",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "OpenSSL Padding Oracle",
        "description": "Padding oracle in AES-NI CBC MAC check.",
    },
    {
        "cve": "CVE-2021-41773",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.49",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "title": "Path traversal and file disclosure",
        "description": "Path traversal and remote command execution in Apache 2.4.49.",
    }
]

PORT_CVE_HINTS = {
    21: {
        "cve": "CVE-2011-2523",
        "service": "ftp",
        "product": "vsFTPd",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "vsFTPd 2.3.4 Backdoor Command Execution",
        "description": "FTP exposure may indicate software vulnerable to the classic vsFTPd backdoor issue. Verify the exact FTP product and version.",
    },
    22: {
        "cve": "CVE-2018-15473",
        "service": "ssh",
        "product": "OpenSSH",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "title": "OpenSSH Username Enumeration",
        "description": "SSH exposure may be affected by OpenSSH username enumeration depending on the exact version in use.",
    },
    80: {
        "cve": "CVE-2021-41773",
        "service": "http",
        "product": "Apache httpd",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "title": "Apache Path Traversal and File Disclosure",
        "description": "HTTP services can expose path traversal and file disclosure issues on vulnerable Apache versions.",
    },
    443: {
        "cve": "CVE-2016-2107",
        "service": "https",
        "product": "OpenSSL",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "OpenSSL Padding Oracle",
        "description": "TLS services may be impacted by OpenSSL cryptographic flaws depending on deployed version.",
    },
    445: {
        "cve": "CVE-2017-0144",
        "service": "smb",
        "product": "Microsoft SMBv1",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "EternalBlue SMB Remote Code Execution",
        "description": "SMB exposure on port 445 is high risk and commonly associated with EternalBlue-class vulnerabilities if SMBv1 is enabled.",
    },
    3306: {
        "cve": "CVE-2012-2122",
        "service": "mysql",
        "product": "MySQL",
        "severity": "HIGH",
        "cvss_score": 6.5,
        "title": "MySQL Authentication Bypass",
        "description": "MySQL services may be affected by authentication bypass issues depending on version and deployment.",
    },
    3389: {
        "cve": "CVE-2019-0708",
        "service": "rdp",
        "product": "Microsoft Remote Desktop Services",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "BlueKeep Remote Desktop Remote Code Execution",
        "description": "RDP exposure on port 3389 is high risk and may be vulnerable to BlueKeep on affected Windows systems.",
    },
    5432: {
        "cve": "CVE-2018-1058",
        "service": "postgresql",
        "product": "PostgreSQL",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "title": "PostgreSQL search_path Privilege Escalation",
        "description": "PostgreSQL services may be impacted by privilege escalation issues depending on configuration and version.",
    },
    5900: {
        "cve": "CVE-2019-15681",
        "service": "vnc",
        "product": "LibVNCServer",
        "severity": "HIGH",
        "cvss_score": 8.8,
        "title": "VNC Authentication Bypass / RCE Risk",
        "description": "VNC exposure is high risk and may map to remote access flaws depending on the deployed implementation.",
    },
    6379: {
        "cve": "CVE-2022-0543",
        "service": "redis",
        "product": "Redis",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "title": "Redis Lua Sandbox Escape",
        "description": "Redis exposure may be vulnerable to sandbox escape and remote code execution depending on version and packaging.",
    },
    8080: {
        "cve": "CVE-2020-1938",
        "service": "http",
        "product": "Apache Tomcat",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "Tomcat AJP / Ghostcat File Read / Inclusion",
        "description": "Services on port 8080 commonly indicate Tomcat or HTTP proxies that may be affected by Ghostcat-style flaws.",
    },
}

PORT_RISK_HINTS = {
    445: {
        "service": "smb",
        "product": "SMB",
        "severity": "HIGH",
        "cvss_score": 8.1,
        "title": "SMB Service Exposure",
        "description": "SMB is exposed on port 445. Validate the supported SMB dialects and patch level before mapping this exposure to a specific CVE such as EternalBlue.",
    },
}

SEVERITY_TO_CVSS = {
    "CRITICAL": 9.8,
    "HIGH": 8.1,
    "MEDIUM": 5.5,
    "LOW": 3.1,
}


def _append_unique(findings, candidate):
    key = (
        candidate.get("port"),
        (candidate.get("cve") or "").upper(),
        (candidate.get("product") or "").lower(),
        candidate.get("title"),
    )
    existing = {
        (
            item.get("port"),
            (item.get("cve") or "").upper(),
            (item.get("product") or "").lower(),
            item.get("title"),
        )
        for item in findings
    }
    if key not in existing:
        findings.append(candidate)


def _default_remediation(service, product, version, title=""):
    return remediation_plan(service, product, version, title)


def _service_matches(vuln, svc_name, product):
    vuln_service = str(vuln.get("service") or "").lower()
    vuln_product = str(vuln.get("product") or "").lower()
    return vuln_service in svc_name or vuln_service in product or vuln_product in product


def _version_matches(expected_version: str, detected_version: str) -> bool:
    expected = str(expected_version or "").strip().lower()
    detected = str(detected_version or "").strip().lower()
    if not expected or not detected:
        return False
    return expected == detected or detected.startswith(expected) or expected.startswith(detected)


def _build_infra_evidence(svc, *, matched_by: str, direct_proof: bool, note: str):
    observed = [
        f"Open port detected: {svc.get('port')}/{svc.get('protocol') or 'tcp'}",
        f"Service identified: {svc.get('service') or 'unknown'}",
    ]
    if svc.get("product"):
        observed.append(f"Product identified: {svc.get('product')}")
    if svc.get("version"):
        observed.append(f"Version identified: {svc.get('version')}")
    observed.append(note)
    return make_evidence(
        observed=observed,
        request={
            "protocol": svc.get("protocol") or "tcp",
            "target_port": svc.get("port"),
            "method": "banner/version detection",
        },
        response={
            "service": svc.get("service") or "unknown",
            "product": svc.get("product") or "",
            "version": svc.get("version") or "",
        },
        conclusion=(
            "Vulnerability confirmed by service and version validation."
            if direct_proof
            else f"Finding is a {matched_by} hypothesis and should be manually verified before external reporting."
        ),
    )


def _build_matched_finding(svc, vuln):
    direct_proof = _version_matches(vuln.get("version"), svc.get("version"))
    evidence = _build_infra_evidence(
        svc,
        matched_by="version-and-product match",
        direct_proof=direct_proof,
        note=f"Matched local rule for {vuln['product']} {vuln['version']}.",
    )
    return enrich_finding(
        {
            "port": svc.get("port"),
            "service": (svc.get("service") or vuln["service"]).lower(),
            "product": svc.get("product") or vuln["product"],
            "version": svc.get("version") or vuln["version"],
            "cve": vuln["cve"],
            "severity": vuln["severity"],
            "cvss_score": vuln.get("cvss_score", SEVERITY_TO_CVSS.get(vuln["severity"])),
            "title": vuln["title"],
            "description": vuln["description"],
            "remediation": vuln.get("remediation") or _default_remediation(svc.get("service"), svc.get("product"), svc.get("version"), vuln["title"]),
        },
        validation="confirmed" if direct_proof else "validated_version",
        confidence_score=95 if direct_proof else 78,
        evidence=evidence,
        source="local_rule_db",
    )


def _build_port_based_finding(svc):
    port = svc.get("port")
    hint = PORT_CVE_HINTS.get(port)
    if not hint:
        return None

    if port == 445 and not _service_indicates_smbv1(svc):
        return None

    service_name = (svc.get("service") or hint["service"]).lower()
    product_name = svc.get("product") or hint["product"]
    version = svc.get("version") or ""
    version_present = bool(version)
    validation = "validated_version" if version_present else "hypothesis"
    confidence = 72 if version_present else 35
    note = (
        f"High-risk service exposed on default port {port}; version data was observed for manual validation."
        if version_present
        else f"High-risk service exposed on default port {port}; no product/version proof was available."
    )
    evidence = _build_infra_evidence(
        svc,
        matched_by="port-based heuristic",
        direct_proof=False,
        note=note,
    )

    return enrich_finding(
        {
            "port": port,
            "service": service_name,
            "product": product_name,
            "version": version,
            "cve": hint["cve"],
            "severity": hint["severity"],
            "cvss_score": hint.get("cvss_score"),
            "title": hint["title"],
            "description": hint["description"],
            "remediation": hint.get("remediation") or _default_remediation(service_name, product_name, version, hint["title"]),
        },
        validation=validation,
        confidence_score=confidence,
        evidence=evidence,
        source="port_heuristic",
    )


def _service_script_text(svc) -> str:
    script_chunks = []
    for script in svc.get("scripts") or []:
        if isinstance(script, dict):
            script_chunks.append(str(script.get("id") or ""))
            script_chunks.append(str(script.get("output") or ""))
        else:
            script_chunks.append(str(script))
    return " ".join(script_chunks).lower()


def _service_indicates_smbv1(svc) -> bool:
    candidates = [
        str(svc.get("service") or ""),
        str(svc.get("product") or ""),
        str(svc.get("version") or ""),
        _service_script_text(svc),
    ]
    combined = " ".join(part for part in candidates if part).lower()
    return "smbv1" in combined or "nt lm 0.12" in combined


def _build_generic_port_risk_finding(svc):
    port = svc.get("port")
    hint = PORT_RISK_HINTS.get(port)
    if not hint:
        return None

    service_name = (svc.get("service") or hint["service"]).lower()
    product_name = svc.get("product") or hint["product"]
    version = svc.get("version") or ""
    evidence = _build_infra_evidence(
        svc,
        matched_by="service exposure",
        direct_proof=False,
        note=f"High-risk service exposed on default port {port}; a specific CVE was not asserted because protocol/version evidence was insufficient.",
    )

    return enrich_finding(
        {
            "port": port,
            "service": service_name,
            "product": product_name,
            "version": version,
            "cve": None,
            "severity": hint["severity"],
            "cvss_score": hint.get("cvss_score"),
            "title": hint["title"],
            "description": hint["description"],
            "remediation": hint.get("remediation") or _default_remediation(service_name, product_name, version, hint["title"]),
        },
        validation="hypothesis",
        confidence_score=55,
        evidence=evidence,
        source="port_exposure",
    )


def fetch_cves_from_nvd(product, version):
    if requests is None:
        return []

    q = f"{product} {version}".strip()
    if not q:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {"keyword": q, "resultsPerPage": 10}

    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        body = resp.json()

        results = []
        for item in body.get("result", {}).get("CVE_Items", []):
            meta = item.get("cve", {}).get("CVE_data_meta", {})
            cve_id = meta.get("ID")
            desc = ""
            desc_list = item.get("cve", {}).get("description", {}).get("description_data", [])
            if desc_list:
                desc = desc_list[0].get("value", "")

            impact = item.get("impact", {})
            severity = "UNKNOWN"
            if impact.get("baseMetricV3"):
                severity = impact["baseMetricV3"].get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
                score = impact["baseMetricV3"].get("cvssV3", {}).get("baseScore")
            elif impact.get("baseMetricV2"):
                severity = impact["baseMetricV2"].get("severity", "UNKNOWN")
                score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore")
            else:
                score = SEVERITY_TO_CVSS.get(severity)

            evidence = make_evidence(
                observed=[f"NVD keyword lookup matched product query: {product} {version}"],
                request={"query": q, "endpoint": url},
                response={"cve": cve_id},
                conclusion="NVD returned a possible match. This is not exploit confirmation and should be validated against the deployed build.",
            )
            results.append(
                enrich_finding(
                    {
                        "cve": cve_id,
                        "severity": severity,
                        "cvss_score": score,
                        "title": desc.split(".")[0][:68] if desc else "NVD matched CVE",
                        "description": desc,
                        "product": product,
                        "version": version,
                        "remediation": _default_remediation("", product, version, desc),
                    },
                    validation="validated_version" if version else "hypothesis",
                    confidence_score=68 if version else 40,
                    evidence=evidence,
                    source="nvd_lookup",
                )
            )

        return results

    except Exception:
        return []


def assess_vulnerabilities(services):
    findings = []
    for svc in services:
        svc_name = (svc.get("service") or "").lower()
        product = (svc.get("product") or "").lower()
        version = (svc.get("version") or "").lower()

        for vuln in VULN_DB:
            if _service_matches(vuln, svc_name, product) and _version_matches(vuln["version"], version):
                _append_unique(findings, _build_matched_finding(svc, vuln))

        port_based = _build_port_based_finding(svc)
        if port_based:
            _append_unique(findings, port_based)
        else:
            generic_port_risk = _build_generic_port_risk_finding(svc)
            if generic_port_risk:
                _append_unique(findings, generic_port_risk)

        if settings.ENABLE_LIVE_NVD_LOOKUPS and product and version:
            remote_cves = fetch_cves_from_nvd(product, version)
            for r in remote_cves:
                candidate = dict(r)
                candidate["port"] = svc.get("port")
                candidate["service"] = svc_name
                candidate["product"] = svc.get("product")
                candidate["version"] = svc.get("version")
                _append_unique(findings, candidate)

    return findings
