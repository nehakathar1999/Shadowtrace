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
        "cwe_ids": ["CWE-400"],
        "weakness_summary": "CWE-400: Uncontrolled Resource Consumption",
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
        "cwe_ids": ["CWE-22"],
        "weakness_summary": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
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
        "cwe_ids": ["CWE-203"],
        "weakness_summary": "CWE-203: Observable Discrepancy",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "title": "OpenSSH Username Enumeration",
        "description": "SSH exposure may be affected by OpenSSH username enumeration depending on the exact version in use.",
    },
    80: {
        "cve": "CVE-2021-41773",
        "service": "http",
        "product": "Apache httpd",
        "cwe_ids": ["CWE-22"],
        "weakness_summary": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
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
        "cwe_ids": ["CWE-287"],
        "weakness_summary": "CWE-287: Improper Authentication",
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
        "cwe_ids": ["CWE-269"],
        "weakness_summary": "CWE-269: Improper Privilege Management",
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
        "cwe_ids": ["CWE-22"],
        "weakness_summary": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "title": "Tomcat AJP / Ghostcat File Read / Inclusion",
        "description": "Services on port 8080 commonly indicate Tomcat or HTTP proxies that may be affected by Ghostcat-style flaws.",
    },
}

PORT_RISK_HINTS = {
    445: {
        "cve": "CVE-2017-0144",
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


LOCAL_CWE_MAP = {
    "CVE-2012-2122": (["CWE-287"], "CWE-287: Improper Authentication"),
    "CVE-2018-1058": (["CWE-269"], "CWE-269: Improper Privilege Management"),
    "CVE-2018-15473": (["CWE-203"], "CWE-203: Observable Discrepancy"),
    "CVE-2020-1938": (["CWE-22"], "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"),
    "CVE-2021-41773": (["CWE-22"], "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"),
    "CVE-2023-44487": (["CWE-400"], "CWE-400: Uncontrolled Resource Consumption"),
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


def _extract_cwe_ids(text: str) -> list[str]:
    tokens = []
    for raw in str(text or "").replace(",", " ").split():
        value = raw.strip().upper().rstrip(".:);")
        if value.startswith("CWE-"):
            if value not in tokens:
                tokens.append(value)
    return tokens


def _local_weakness_metadata(cve_id: str | None = None, *texts: str) -> tuple[list[str], str]:
    cve_key = str(cve_id or "").strip().upper()
    if cve_key in LOCAL_CWE_MAP:
        return LOCAL_CWE_MAP[cve_key]

    collected = []
    for text in texts:
        for cwe_id in _extract_cwe_ids(text):
            if cwe_id not in collected:
                collected.append(cwe_id)

    summary = f"Mapped weakness identifiers: {', '.join(collected)}" if collected else ""
    return collected, summary


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
    cwe_ids, weakness_summary = _local_weakness_metadata(
        vuln.get("cve"),
        vuln.get("title"),
        vuln.get("description"),
        vuln.get("weakness_summary"),
    )
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
            "cwe_ids": cwe_ids or vuln.get("cwe_ids") or [],
            "weakness_summary": weakness_summary or vuln.get("weakness_summary") or "",
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
    cwe_ids, weakness_summary = _local_weakness_metadata(
        hint.get("cve"),
        hint.get("title"),
        hint.get("description"),
        hint.get("weakness_summary"),
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
            "cwe_ids": cwe_ids or hint.get("cwe_ids") or [],
            "weakness_summary": weakness_summary or hint.get("weakness_summary") or "",
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


def _build_script_finding(svc, script_id: str, output: str):
    output_text = str(output or "").strip()
    lowered = output_text.lower()
    severity = "MEDIUM"
    score = 5.5
    if any(term in lowered for term in ("critical", "remote code execution", "rce")):
        severity = "CRITICAL"
        score = 9.5
    elif any(term in lowered for term in ("high", "vulnerable", "cve-")):
        severity = "HIGH"
        score = 8.1

    cve_match = None
    for token in output_text.replace(",", " ").split():
        token_upper = token.strip().upper().rstrip(".:")
        if token_upper.startswith("CVE-"):
            cve_match = token_upper
            break
    cwe_ids, weakness_summary = _local_weakness_metadata(cve_match, script_id, output_text)

    evidence = _build_infra_evidence(
        svc,
        matched_by="nmap-nse-signature",
        direct_proof="vulnerable" in lowered or bool(cve_match),
        note=f"NSE script {script_id} reported: {output_text[:180]}",
    )
    return enrich_finding(
        {
            "port": svc.get("port"),
            "service": (svc.get("service") or "unknown").lower(),
            "product": svc.get("product") or "",
            "version": svc.get("version") or "",
            "cve": cve_match,
            "severity": severity,
            "cvss_score": score,
            "title": f"Nmap NSE detection: {script_id}",
            "description": output_text or f"NSE script {script_id} reported a vulnerability indication.",
            "cwe_ids": cwe_ids,
            "weakness_summary": weakness_summary,
            "remediation": _default_remediation(svc.get("service"), svc.get("product"), svc.get("version"), script_id),
        },
        validation="confirmed" if "vulnerable" in lowered else "validated_version",
        confidence_score=90 if "vulnerable" in lowered else 76,
        evidence=evidence,
        source="nmap_vuln_script",
    )


def _findings_from_scripts(svc):
    findings = []
    for script in svc.get("scripts") or []:
        script_id = str(script.get("id") or "").strip()
        output = str(script.get("output") or "").strip()
        if not script_id or not output:
            continue
        lowered = output.lower()
        if script_id.startswith("vuln") or "vulnerable" in lowered or "cve-" in lowered:
            findings.append(_build_script_finding(svc, script_id, output))
    return findings


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
            "cve": hint.get("cve"),
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


def _collect_nvd_weaknesses(item):
    cwe_ids = []
    weakness_labels = []

    # NVD 2.0 format
    weakness_blocks = item.get("cve", {}).get("weaknesses", []) or []
    for block in weakness_blocks:
        for desc in block.get("description", []) or []:
            value = str(desc.get("value") or "").strip()
            if not value:
                continue
            value_upper = value.upper()
            if value_upper.startswith("CWE-") and value_upper not in cwe_ids:
                cwe_ids.append(value_upper)
            if value not in weakness_labels:
                weakness_labels.append(value)

    # Legacy NVD 1.0 format
    legacy_problemtypes = item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []) or []
    for block in legacy_problemtypes:
        for desc in block.get("description", []) or []:
            value = str(desc.get("value") or "").strip()
            if not value:
                continue
            value_upper = value.upper()
            if value_upper.startswith("CWE-") and value_upper not in cwe_ids:
                cwe_ids.append(value_upper)
            if value not in weakness_labels:
                weakness_labels.append(value)

    filtered_labels = [
        value for value in weakness_labels
        if value.upper() not in {"NVD-CWE-NOINFO", "NVD-CWE-OTHER"}
    ]
    summary = ", ".join(filtered_labels[:3]) if filtered_labels else ""
    return cwe_ids, summary


def _extract_nvd_severity_and_score(item):
    cve_payload = item.get("cve", {})
    metrics = cve_payload.get("metrics") or {}
    impact = item.get("impact", {})

    metric_sets = [
        metrics.get("cvssMetricV31"),
        metrics.get("cvssMetricV30"),
        metrics.get("cvssMetricV2"),
    ]
    for metric_list in metric_sets:
        if not metric_list:
            continue
        metric = metric_list[0] or {}
        cvss = metric.get("cvssData") or metric.get("cvssV2") or {}
        severity = metric.get("baseSeverity") or cvss.get("baseSeverity") or metric.get("severity")
        score = cvss.get("baseScore")
        if severity or score is not None:
            return (severity or "UNKNOWN"), score

    if impact.get("baseMetricV3"):
        cvss = impact["baseMetricV3"].get("cvssV3", {})
        return cvss.get("baseSeverity", "UNKNOWN"), cvss.get("baseScore")
    if impact.get("baseMetricV2"):
        cvss = impact["baseMetricV2"].get("cvssV2", {})
        return impact["baseMetricV2"].get("severity", "UNKNOWN"), cvss.get("baseScore")
    return "UNKNOWN", None


def fetch_cves_from_nvd(product, version):
    if requests is None:
        return []

    q = f"{product} {version}".strip()
    if not q:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keyword": q, "resultsPerPage": 10}

    try:
        resp = requests.get(url, params=params, timeout=10)
        resp.raise_for_status()
        body = resp.json()

        results = []
        for item in body.get("vulnerabilities", []) or body.get("result", {}).get("CVE_Items", []):
            cve_payload = item.get("cve", {})
            meta = cve_payload.get("CVE_data_meta", {})
            cve_id = cve_payload.get("id") or meta.get("ID")
            desc = ""
            desc_list = cve_payload.get("descriptions") or cve_payload.get("description", {}).get("description_data", [])
            if desc_list:
                desc = next((entry.get("value", "") for entry in desc_list if entry.get("lang", "en") == "en"), desc_list[0].get("value", ""))

            severity, score = _extract_nvd_severity_and_score(item)
            if score is None:
                score = SEVERITY_TO_CVSS.get(severity)

            cwe_ids, weakness_summary = _collect_nvd_weaknesses(item)
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
                        "cwe_ids": cwe_ids,
                        "weakness_summary": weakness_summary,
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

        for script_finding in _findings_from_scripts(svc):
            _append_unique(findings, script_finding)

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
