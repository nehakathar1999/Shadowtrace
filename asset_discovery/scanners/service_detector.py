import re

import nmap

from config.settings import settings
from scanners.banner_grabber import enrich_services_with_banners

scanner = nmap.PortScanner()


COMMON_PORT_HINTS = {
    21: {"service": "ftp", "product": "FTP"},
    22: {"service": "ssh", "product": "SSH"},
    25: {"service": "smtp", "product": "SMTP"},
    53: {"service": "dns", "product": "DNS"},
    80: {"service": "http", "product": "HTTP"},
    110: {"service": "pop3", "product": "POP3"},
    143: {"service": "imap", "product": "IMAP"},
    443: {"service": "https", "product": "HTTPS"},
    445: {"service": "smb", "product": "SMB"},
    3306: {"service": "mysql", "product": "MySQL"},
    3389: {"service": "rdp", "product": "Remote Desktop"},
    5432: {"service": "postgresql", "product": "PostgreSQL"},
    5900: {"service": "vnc", "product": "VNC"},
    6379: {"service": "redis", "product": "Redis"},
    8000: {"service": "http", "product": "HTTP"},
    8080: {"service": "http", "product": "HTTP"},
    8443: {"service": "https", "product": "HTTPS"},
    9443: {"service": "https", "product": "HTTPS"},
}


def _extract_port_scripts(port_entry):
    scripts = []
    raw_scripts = (port_entry or {}).get("script", {}) or {}
    for script_id, output in raw_scripts.items():
        scripts.append({
            "id": script_id,
            "output": output,
        })
    return scripts


def _derive_smb_version(product, version, scripts):
    text_parts = [
        str(product or ""),
        str(version or ""),
        " ".join(str(script.get("output") or "") for script in (scripts or [])),
    ]
    combined = " ".join(part for part in text_parts if part).lower()

    if not combined:
        return version or ""

    if "nt lm 0.12 (smbv1)" in combined or "smbv1" in combined:
        return "SMBv1"
    if "smb 2" in combined or "smb2" in combined:
        return "SMBv2"
    if "smb 3" in combined or "smb3" in combined:
        return "SMBv3"

    return version or ""


def _first_non_empty(*values):
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _normalize_cpe(cpe):
    if isinstance(cpe, list):
        return [str(item).strip() for item in cpe if str(item).strip()]
    text = str(cpe or "").strip()
    return [text] if text else []


def _parse_cpe_details(cpe):
    for entry in _normalize_cpe(cpe):
        parts = entry.split(":")
        if len(parts) >= 5:
            vendor = parts[3].replace("_", " ").strip()
            product = parts[4].replace("_", " ").strip()
            version = parts[5].replace("_", " ").strip() if len(parts) >= 6 else ""
            product_name = " ".join(part for part in (vendor, product) if part).strip()
            return product_name, version
    return "", ""


def _parse_banner_details(service_name, banner):
    text = str(banner or "").strip()
    if not text:
        return "", ""

    ssh_match = re.search(r"SSH-\d+\.\d+-([A-Za-z0-9._-]+)", text, re.IGNORECASE)
    if ssh_match:
        token = ssh_match.group(1)
        product_match = re.match(r"([A-Za-z-]+)[_/ -]?([0-9][A-Za-z0-9._-]*)?", token)
        if product_match:
            product = product_match.group(1) or "SSH"
            version = product_match.group(2) or ""
            return product, version
        return token, ""

    server_match = re.search(r"(?im)^server:\s*([^\r\n]+)", text)
    if server_match:
        server_value = server_match.group(1).strip()
        if "/" in server_value:
            product, version = server_value.split("/", 1)
            return product.strip(), version.strip()
        return server_value, ""

    if str(service_name or "").lower() == "redis":
        redis_match = re.search(r"redis[_ -]?server[_ -]?v?([0-9][A-Za-z0-9.\-]*)", text, re.IGNORECASE)
        if redis_match:
            return "Redis", redis_match.group(1)

    return "", ""


def _infer_service_name(port, raw_name, banner, cpe, scripts):
    normalized = str(raw_name or "").strip().lower()
    if normalized and normalized not in {"unknown", "tcpwrapped"}:
        if normalized == "ssl/http":
            return "https"
        if normalized == "http-proxy":
            return "http"
        return normalized

    cpe_product, _ = _parse_cpe_details(cpe)
    cpe_lower = cpe_product.lower()
    if "openssh" in cpe_lower:
        return "ssh"
    if "apache" in cpe_lower or "nginx" in cpe_lower or "iis" in cpe_lower or "http" in cpe_lower:
        return "https" if port in {443, 8443, 9443} else "http"
    if "mysql" in cpe_lower:
        return "mysql"
    if "postgres" in cpe_lower:
        return "postgresql"

    banner_text = str(banner or "").lower()
    if "ssh-" in banner_text:
        return "ssh"
    if "http/" in banner_text or "server:" in banner_text:
        return "https" if port in {443, 8443, 9443} else "http"

    script_text = " ".join(str(script.get("output") or "") for script in (scripts or [])).lower()
    if "ssh" in script_text:
        return "ssh"
    if "http" in script_text:
        return "https" if port in {443, 8443, 9443} else "http"

    return COMMON_PORT_HINTS.get(port, {}).get("service", "unknown")


def _infer_product_and_version(port, service_name, raw_product, raw_version, extra_info, cpe, banner):
    product = str(raw_product or "").strip()
    version = str(raw_version or "").strip()

    cpe_product, cpe_version = _parse_cpe_details(cpe)
    banner_product, banner_version = _parse_banner_details(service_name, banner)

    product = _first_non_empty(product, banner_product, cpe_product, COMMON_PORT_HINTS.get(port, {}).get("product"))
    version = _first_non_empty(version, banner_version, cpe_version)

    if not version and extra_info:
        version_match = re.search(r"\b(\d+(?:\.\d+){1,3}[A-Za-z0-9._-]*)\b", str(extra_info))
        if version_match:
            version = version_match.group(1)

    if product.upper() in {"HTTP", "HTTPS"} and banner_product:
        product = banner_product

    return product, version


def _build_service_entry(port, proto, service_data, host_scripts, host_os_matches, banner=""):
    service_data = service_data or {}
    scripts = _extract_port_scripts(service_data)
    raw_name = service_data.get("name")
    raw_product = service_data.get("product")
    raw_version = service_data.get("version")
    extra_info = service_data.get("extrainfo")
    cpe = service_data.get("cpe")

    service_name = _infer_service_name(port, raw_name, banner, cpe, scripts)
    product, version = _infer_product_and_version(
        port,
        service_name,
        raw_product,
        raw_version,
        extra_info,
        cpe,
        banner,
    )

    if port == 445 or str(service_name or "").lower() in {"microsoft-ds", "netbios-ssn", "smb"}:
        normalized_version = _derive_smb_version(product, version, scripts)
        if normalized_version:
            version = normalized_version
        if not product:
            product = "SMB"
        service_name = "smb"

    return {
        "port": port,
        "protocol": proto,
        "service": service_name or COMMON_PORT_HINTS.get(port, {}).get("service", "unknown"),
        "product": product,
        "version": version,
        "extra_info": extra_info,
        "cpe": cpe,
        "state": service_data.get("state") or "open",
        "scripts": scripts,
        "host_scripts": host_scripts,
        "os_matches": host_os_matches,
    }


def _normalize_ports(ports):
    port_numbers = []
    for item in ports or []:
        if isinstance(item, dict):
            value = item.get("port")
        else:
            value = item
        try:
            port_numbers.append(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(set(port_numbers))


def _fallback_services_for_ports(port_numbers):
    return [
        {
            "port": port,
            "protocol": "tcp",
            "service": COMMON_PORT_HINTS.get(port, {}).get("service", "unknown"),
            "product": COMMON_PORT_HINTS.get(port, {}).get("product", ""),
            "version": "",
            "extra_info": "",
            "cpe": "",
            "state": "open",
            "scripts": [],
            "host_scripts": [],
            "os_matches": [],
        }
        for port in port_numbers
    ]


def detect_services(ip, ports=None):
    """
    Run an Nmap service/version scan.

    If `ports` is provided, only those ports will be checked.
    Returns a list of dicts with port, service, product, and version.
    """

    args = (
        f"-Pn -A -sV -O --osscan-limit --version-light --script vuln "
        f"--host-timeout {settings.SERVICE_SCAN_TIMEOUT}s --max-retries 1"
    )

    port_numbers = _normalize_ports(ports)
    if not port_numbers:
        return []

    port_list = ",".join(str(p) for p in port_numbers)
    args += f" -p {port_list}"
    if 445 in port_numbers:
        args += " --script smb-protocols,smb-os-discovery"

    try:
        scanner.scan(ip, arguments=args)
    except Exception as e:
        print(f"[service_detector] nmap scan failed for {ip} with args '{args}': {e}")
        enriched = enrich_services_with_banners(ip, _fallback_services_for_ports(port_numbers))
        results = []
        for item in enriched:
            rebuilt = _build_service_entry(
                item.get("port"),
                item.get("protocol") or "tcp",
                item,
                [],
                [],
                item.get("banner") or "",
            )
            rebuilt.update({
                "banner": item.get("banner"),
                "banner_source": item.get("banner_source"),
                "banner_status": item.get("banner_status"),
            })
            results.append(rebuilt)
        return results

    services = []
    host_os_matches = []
    host_scripts = []
    seen_ports = set()

    if ip in scanner.all_hosts():
        for match in scanner[ip].get("osmatch", []) or []:
            host_os_matches.append({
                "name": match.get("name"),
                "accuracy": match.get("accuracy"),
                "line": match.get("line"),
            })

        for script in scanner[ip].get("hostscript", []) or []:
            host_scripts.append({
                "id": script.get("id"),
                "output": script.get("output"),
            })

        for proto in scanner[ip].all_protocols():
            for port, service in scanner[ip][proto].items():
                if service.get("state") != "open":
                    continue
                seen_ports.add(int(port))
                services.append(_build_service_entry(port, proto, service, host_scripts, host_os_matches))

    for port in port_numbers:
        if port not in seen_ports:
            services.append(_build_service_entry(port, "tcp", {"state": "open"}, host_scripts, host_os_matches))

    enriched_services = enrich_services_with_banners(ip, services)
    finalized = []
    for item in enriched_services:
        rebuilt = _build_service_entry(
            item.get("port"),
            item.get("protocol") or "tcp",
            item,
            item.get("host_scripts") or host_scripts,
            item.get("os_matches") or host_os_matches,
            item.get("banner") or "",
        )
        rebuilt.update({
            "banner": item.get("banner"),
            "banner_source": item.get("banner_source"),
            "banner_status": item.get("banner_status"),
        })
        finalized.append(rebuilt)

    finalized.sort(key=lambda entry: int(entry.get("port") or 0))
    return finalized
