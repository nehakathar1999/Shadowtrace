import nmap
from config.settings import settings

scanner = nmap.PortScanner()


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

def detect_services(ip, ports=None):
    """
    Run an Nmap service/version scan.

    If `ports` is provided, only those ports will be checked.
    Returns a list of dicts with port, service, product, and version.
    """

    #args = f"-Pn -sV --version-light --host-timeout {settings.SERVICE_SCAN_TIMEOUT}s --max-retries 1"
    args = f"-Pn -sV -O --osscan-limit --version-light --host-timeout {settings.SERVICE_SCAN_TIMEOUT}s --max-retries 1"

    # ✅ FIX: Normalize ports safely
    port_numbers = []
    if ports:
        for p in ports:
            if isinstance(p, dict):
                # extract port from dict
                if "port" in p:
                    port_numbers.append(p["port"])
            elif isinstance(p, int):
                port_numbers.append(p)
            elif isinstance(p, str) and p.isdigit():
                port_numbers.append(int(p))

    if not port_numbers:
        # Avoid full 1-65535 scans in the request path; they are too slow and
        # cause the frontend to stall at 95% waiting for a response.
        return []
    else:
        # remove duplicates + sort
        port_list = ",".join(str(p) for p in sorted(set(port_numbers)))
        args += f" -p {port_list}"
        if 445 in port_numbers:
            args += " --script smb-protocols,smb-os-discovery"

    # Run scan
    try:
        scanner.scan(ip, arguments=args)
    except Exception as e:
        print(f"[service_detector] nmap scan failed for {ip} with args '{args}': {e}")
        return []

    services = []

    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            for port, service in scanner[ip][proto].items():

                if service.get("state") != "open":
                    continue

                scripts = _extract_port_scripts(service)
                service_name = service.get("name")
                product = service.get("product")
                version = service.get("version")

                if port == 445 or str(service_name or "").lower() in {"microsoft-ds", "netbios-ssn", "smb"}:
                    normalized_version = _derive_smb_version(product, version, scripts)
                    if normalized_version:
                        version = normalized_version
                    if not product:
                        product = "SMB"
                    if not service_name or str(service_name).lower() == "microsoft-ds":
                        service_name = "smb"

                services.append({
                    "port": port,
                    "protocol": proto,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "scripts": scripts,
                })

    return services
