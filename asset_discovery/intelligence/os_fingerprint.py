import ipaddress
import json
import os
import re
import socket
import subprocess

import nmap
from config.settings import settings

scanner = nmap.PortScanner()


def _local_ipv4_addresses():
    ips = {"127.0.0.1"}
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, family=socket.AF_INET)
        ips.update(info[4][0] for info in infos)
    except Exception:
        pass
    try:
        _, _, host_ips = socket.gethostbyname_ex(socket.gethostname())
        ips.update(host_ips or [])
    except Exception:
        pass
    if os.name == "nt":
        try:
            # Capture all NIC IPv4 addresses (including VPN/virtual adapters)
            # because getaddrinfo/gethostbyname_ex can miss some interfaces.
            output = subprocess.check_output(
                ["ipconfig"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=3,
                encoding="utf-8",
                errors="ignore",
            )
            ip_matches = re.findall(r"IPv4[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", output)
            ips.update(ip_matches)
        except Exception:
            pass
    return ips


def _is_local_target(ip):
    text = str(ip or "").strip()
    if not text:
        return False
    try:
        target = ipaddress.ip_address(text)
    except ValueError:
        return False
    if target.is_loopback:
        return True
    return text in _local_ipv4_addresses()


def _detect_local_windows_edition():
    if os.name != "nt":
        return None
    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | "
        "Select-Object ProductName,CurrentBuildNumber | ConvertTo-Json -Compress",
    ]
    try:
        output = subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
        if not output:
            return None
        info = json.loads(output)
        product = str(info.get("ProductName") or "").strip()
        build_text = str(info.get("CurrentBuildNumber") or "").strip()
        build = int(build_text) if build_text.isdigit() else 0

        # Some Windows 11 installs still expose ProductName as "Windows 10 ...".
        # Build >= 22000 is Windows 11, so normalize the major label while
        # preserving the edition suffix (e.g. "Pro", "Enterprise").
        if product.lower().startswith("windows 10") and build >= 22000:
            return re.sub(r"^Windows 10", "Windows 11", product, flags=re.IGNORECASE)

        return product or None
    except Exception:
        return None


def _parse_accuracy(value):
    text = str(value or "").strip().rstrip("%")
    return int(text) if text.isdigit() else 0


def _score_os_match(match):
    name = str(match.get("name") or "").strip().lower()
    accuracy = _parse_accuracy(match.get("accuracy"))

    penalty = 0
    if " or " in name:
        penalty += 6
    if " - " in name:
        penalty += 5
    if "windows 10" in name and "windows 11" in name:
        penalty += 4
    if "unknown" in name:
        penalty += 10

    bonus = 0
    if "windows 11" in name:
        bonus += 4
    if "server 2022" in name or "server 2019" in name or "server 2016" in name:
        bonus += 3

    return accuracy + bonus - penalty


def _normalize_os_name(name):
    text = str(name or "").strip()
    lower = text.lower()

    # Nmap often reports Windows 10/11 desktop builds as a broad shared range.
    # Prefer a cleaner family label over showing a misleading version span.
    if "windows 10" in lower and "windows 11" in lower:
        return "Microsoft Windows 11"

    if "windows 11" in lower:
        return "Microsoft Windows 11"

    if "windows 10" in lower:
        return "Microsoft Windows 10"

    return text


def _select_best_os_match(matches):
    valid_matches = [match for match in (matches or []) if match.get("name")]
    if not valid_matches:
        return None
    return max(valid_matches, key=_score_os_match)


def _normalize_tokens(values):
    tokens = []
    for value in values:
        if not value:
            continue
        tokens.append(str(value).strip().lower())
    return tokens


def _contains_any(haystack, needles):
    return any(needle in item for item in haystack for needle in needles)


def _service_has_port(services, port):
    for svc in services or []:
        try:
            if int(svc.get("port")) == int(port):
                return True
        except Exception:
            continue
    return False


def _extract_windows_from_script_output(output):
    text = str(output or "").strip()
    if not text:
        return None

    # Typical smb-os-discovery output includes a line like:
    # "OS: Windows 10 Pro 19045"
    match = re.search(r"OS:\s*([^\r\n]+)", text, flags=re.IGNORECASE)
    candidate = match.group(1).strip() if match else text.strip()
    if "windows" not in candidate.lower():
        return None
    return candidate


def _detect_windows_via_smb(ip):
    try:
        smb_scanner = nmap.PortScanner()
        smb_scanner.scan(
            ip,
            arguments=(
                f"-Pn -p445 --script smb-os-discovery "
                f"--host-timeout {settings.OS_SCAN_TIMEOUT}s --max-retries 1"
            ),
        )
        if ip not in smb_scanner.all_hosts():
            return None

        host_data = smb_scanner[ip]

        for item in host_data.get("hostscript", []) or []:
            if str(item.get("id", "")).lower() == "smb-os-discovery":
                detected = _extract_windows_from_script_output(item.get("output"))
                if detected:
                    return detected

        tcp_data = host_data.get("tcp", {}) or {}
        smb_port = tcp_data.get(445, {}) or {}
        scripts = smb_port.get("script", {}) or {}
        for key, value in scripts.items():
            if "smb-os-discovery" in str(key).lower():
                detected = _extract_windows_from_script_output(value)
                if detected:
                    return detected
    except Exception:
        return None

    return None


def infer_os_from_context(services=None, vendor="Unknown", device_type="Unknown Device", hostname="Unknown"):
    services = services or []
    haystack = _normalize_tokens(
        [vendor, device_type, hostname]
        + [svc.get("service") for svc in services]
        + [svc.get("product") for svc in services]
        + [svc.get("version") for svc in services]
    )

    if not haystack:
        return {"name": "Unknown", "family": "Unknown", "accuracy": "N/A", "source": "unavailable"}

    windows_markers = [
        "microsoft", "windows", "microsoft-ds", "msrpc", "netbios", "winrm",
        "iis", "rdp", "smb", "sql server", "mssql",
    ]
    linux_markers = [
        "ubuntu", "debian", "centos", "red hat", "alpine", "linux", "openssh",
        "apache", "nginx", "postgresql", "mysql", "redis", "docker",
    ]
    macos_markers = [
        "apple", "darwin", "bonjour", "airplay", "macos", "os x",
    ]
    network_markers = [
        "cisco", "juniper", "aruba", "mikrotik", "ubiquiti", "router", "switch", "fortinet",
    ]
    printer_markers = [
        "printer", "jetdirect", "hp", "epson", "canon", "brother", "xerox",
    ]
    iot_markers = [
        "hikvision", "dahua", "axis", "camera", "rtsp", "iot", "embedded",
    ]

    if _contains_any(haystack, windows_markers):
        return {"name": "Windows", "family": "Windows", "accuracy": "High", "source": "service/vendor inference"}

    if _contains_any(haystack, macos_markers):
        return {"name": "macOS / iOS", "family": "Apple", "accuracy": "Medium", "source": "service/vendor inference"}

    if _contains_any(haystack, linux_markers):
        distro_map = [
            ("ubuntu", "Ubuntu Linux"),
            ("debian", "Debian Linux"),
            ("centos", "CentOS Linux"),
            ("red hat", "Red Hat Linux"),
            ("alpine", "Alpine Linux"),
        ]
        distro = next((label for marker, label in distro_map if _contains_any(haystack, [marker])), "Linux")
        return {"name": distro, "family": "Linux", "accuracy": "Medium", "source": "service/vendor inference"}

    if _contains_any(haystack, network_markers):
        return {"name": "Network Appliance", "family": "Embedded / Network OS", "accuracy": "Medium", "source": "device inference"}

    if _contains_any(haystack, printer_markers):
        return {"name": "Printer / Embedded OS", "family": "Embedded", "accuracy": "Medium", "source": "device inference"}

    if _contains_any(haystack, iot_markers):
        return {"name": "Embedded Linux / IoT", "family": "Embedded", "accuracy": "Low", "source": "device inference"}

    return {"name": "Unknown", "family": "Unknown", "accuracy": "N/A", "source": "unavailable"}


def detect_os(ip):
    details = detect_os_details(ip)
    return details["name"]


def detect_os_details(ip, services=None, vendor="Unknown", device_type="Unknown Device", hostname="Unknown"):
    local_edition = _detect_local_windows_edition() if _is_local_target(ip) else None
    if local_edition:
        return {
            "name": local_edition,
            "family": "Windows",
            "accuracy": "Exact",
            "source": "local system",
        }

    try:
        scanner.scan(
            ip,
            arguments=f"-Pn -O --osscan-limit --host-timeout {settings.OS_SCAN_TIMEOUT}s --max-retries 1"
        )
        osmatch = scanner[ip]["osmatch"]

        if osmatch:
            best_match = _select_best_os_match(osmatch)
            classes = best_match.get("osclass") or []
            family = classes[0].get("osfamily") if classes else best_match.get("name", "Unknown")
            accuracy = best_match.get("accuracy", "N/A")
            normalized_name = _normalize_os_name(best_match.get("name", "Unknown"))
            if "windows" in str(normalized_name).lower() and _service_has_port(services, 445):
                smb_name = _detect_windows_via_smb(ip)
                if smb_name:
                    return {
                        "name": smb_name,
                        "family": "Windows",
                        "accuracy": "Medium",
                        "source": "smb-os-discovery",
                    }
            return {
                "name": normalized_name,
                "family": family or "Unknown",
                "accuracy": f"{accuracy}%" if str(accuracy).isdigit() else str(accuracy or "N/A"),
                "source": "nmap",
            }
    except Exception:
        pass

    inferred = infer_os_from_context(
        services=services,
        vendor=vendor,
        device_type=device_type,
        hostname=hostname,
    )
    if str(inferred.get("name", "")).strip().lower() == "windows" and _service_has_port(services, 445):
        smb_name = _detect_windows_via_smb(ip)
        if smb_name:
            return {
                "name": smb_name,
                "family": "Windows",
                "accuracy": "Medium",
                "source": "smb-os-discovery",
            }

    return inferred
