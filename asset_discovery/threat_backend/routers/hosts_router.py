"""
Hosts Router
Store and retrieve multi-host scan results with device classification,
criticality scoring, and full vulnerability analysis.
"""
import re, uuid
from datetime import datetime
from fastapi import APIRouter, HTTPException, Request
from typing import Optional
from loguru import logger

from threat_backend.database import get_db
from threat_backend.services.asset_scanner_service import AssetScannerService

router = APIRouter(prefix="/api/hosts", tags=["Hosts"])
_scanner = AssetScannerService()


# ── Device Type Detection ─────────────────────────────────────────────────────

def _detect_device_type(scan_obj: dict) -> str:
    """Classify device based on OS, ports, services."""
    os_raw   = (scan_obj.get("os_guess") or scan_obj.get("os") or "").lower()
    ports    = scan_obj.get("open_ports") or scan_obj.get("ports") or []
    services = [str(p.get("service","")).lower() for p in ports]
    products = [str(p.get("product","")).lower() for p in ports]
    port_nums = [int(p.get("port",0)) for p in ports]

    # Mobile
    if any(k in os_raw for k in ["android","ios","iphone","ipad"]):
        return "Mobile"

    # IoT / OT
    iot_ports    = {1883, 8883, 5683, 1900, 5353, 47808, 102, 502, 20000}
    iot_services = {"mqtt","coap","upnp","mdns","bacnet","modbus","dnp3","zigbee","zwave"}
    if (set(port_nums) & iot_ports) or any(s in iot_services for s in services):
        return "IoT / OT"

    # Printer
    if any(k in os_raw for k in ["printer","jetdirect","cups"]) or 9100 in port_nums:
        return "Printer"

    # Network Device
    if any(k in os_raw for k in ["cisco","juniper","fortinet","paloalto","router","switch","firewall"]):
        return "Network Device"
    if any(s in services for s in ["snmp","telnet"]) and not any(k in os_raw for k in ["windows","linux"]):
        return "Network Device"

    # Virtualization / Hypervisor
    if any(k in os_raw for k in ["vmware","esxi","hyper-v","xen","proxmox"]):
        return "Hypervisor"
    if any(k in products for k in ["vmware","esxi"]) or set(port_nums) & {902, 912, 443}:
        if any(k in products for k in ["vmware"]):
            return "Hypervisor"

    # Server
    server_services = {"http","https","mysql","postgresql","mssql","mongodb","redis",
                       "smtp","ftp","ldap","kerberos","msrpc","microsoft-ds","netbios-ssn",
                       "vmware-auth","postgresql","microsoft httpapi"}
    server_ports    = {80,443,21,25,3306,5432,1433,27017,6379,8080,8443,389,88,135,139,445}
    if (any(k in os_raw for k in ["server","ubuntu","debian","centos","rhel","fedora","red hat"])):
        return "Server"
    if (set(port_nums) & server_ports) or any(s in server_services for s in services):
        if "windows" in os_raw:
            return "Windows Workstation" if not any(k in os_raw for k in ["server"]) else "Server"
        return "Server"

    # Workstation
    if "windows" in os_raw:
        return "Windows Workstation"
    if any(k in os_raw for k in ["ubuntu","debian","linux","fedora","mint","manjaro","arch"]):
        return "Linux Workstation"
    if any(k in os_raw for k in ["macos","mac os","darwin","apple"]):
        return "macOS Device"

    return "Unknown Device"


def _detect_criticality(scan_result: dict) -> str:
    """Derive criticality from risk summary."""
    risk = (scan_result.get("risk_summary") or {}).get("overall_risk", "LOW")
    return risk  # CRITICAL / HIGH / MEDIUM / LOW


def _detect_status(scan_obj: dict) -> str:
    status = (scan_obj.get("status") or scan_obj.get("host_status") or "up").lower()
    return "Up" if status == "up" else "Down"


def _get_detected_info(scan_obj: dict) -> str:
    """Build a short 'detected' summary string."""
    os_raw = scan_obj.get("os_guess") or scan_obj.get("os") or ""
    os_clean = re.sub(r'\s*\(accuracy[^)]*\)', '', os_raw).strip()
    ports = scan_obj.get("open_ports") or scan_obj.get("ports") or []
    services = [p.get("service","") for p in ports if p.get("service")]
    top_services = ", ".join(list(dict.fromkeys(services))[:4])
    if os_clean and top_services:
        return f"{os_clean} · {top_services}"
    return os_clean or top_services or "—"


# ── Map JSON to internal format (reuse from scanner_router) ───────────────────

def _map_json_scan(scan_obj: dict) -> dict:
    import re as _re
    host        = scan_obj.get("host") or scan_obj.get("resolved_ip") or "unknown"
    host_status = (scan_obj.get("status") or scan_obj.get("host_status") or "up").lower()
    if host_status not in ("up","down"): host_status = "up"

    os_raw   = scan_obj.get("os_guess") or scan_obj.get("os") or ""
    os_raw   = os_raw if os_raw else ""  # handle null values
    os_clean = _re.sub(r'\s*\(accuracy[^)]*\)', '', os_raw).strip()
    os_clean = _re.sub(r'\s*-\s*[\w\s]+ \(accuracy.*', '', os_clean).strip()

    hostnames = scan_obj.get("hostnames") or []
    hostname  = hostnames[0] if hostnames else ""

    nse_map = {}
    for nse in scan_obj.get("nse_findings") or []:
        # Handle both dict format {"port":22,"script":"...","output":"..."}
        # and plain string format "Apache outdated version detected"
        if isinstance(nse, dict):
            p = nse.get("port")
            if p:
                nse_map.setdefault(p, []).append(f"{nse.get('script','')}: {nse.get('output','')[:100]}")
        elif isinstance(nse, str) and nse.strip():
            # Store as general note (not port-specific)
            nse_map.setdefault("_general", []).append(nse[:150])

    ports = []
    seen  = set()

    INSECURE_PORT_MAP = {
        "smb":(445,"microsoft-ds","SMB"), "netbios":(139,"netbios-ssn","NetBIOS"),
        "telnet":(23,"telnet","Telnet"), "ftp":(21,"ftp","FTP"),
        "rdp":(3389,"ms-wbt-server","RDP"), "vnc":(5900,"vnc","VNC"),
    }

    def add(port_num, protocol="tcp", service="", product="", version="", extrainfo="", state="open"):
        if port_num in seen: return
        seen.add(port_num)
        nse_info = " | ".join(nse_map.get(port_num, []))
        if not version and nse_info:
            vm = _re.search(r'Version[:\s]+([\d\.]+)', nse_info, _re.IGNORECASE)
            if vm: version = vm.group(1)
        full_product = product
        if extrainfo and extrainfo not in full_product:
            full_product = f"{full_product} ({extrainfo})".strip(" ()")
        ports.append({"port":int(port_num),"state":state,"protocol":protocol.lower(),
                      "service":service,"product":full_product,"version":version})

    # Support both "open_ports" (teammate format) and "ports" (direct format)
    # Also support port objects with "state" field or assume "open" if missing
    all_ports = scan_obj.get("open_ports") or scan_obj.get("ports") or []
    for p in all_ports:
        if not isinstance(p, dict):
            continue
        state = p.get("state", "open").lower()
        add(
            p.get("port", 0),
            p.get("protocol", "tcp"),
            p.get("service", ""),
            p.get("product", ""),
            p.get("version", ""),
            p.get("extrainfo", ""),
            state,
        )

    for s in scan_obj.get("services") or []:
        # Handle both dict format {"port":80,"service":"http",...}
        # and plain string format "No response from host"
        if isinstance(s, dict):
            p = s.get("port", 0)
            if p and p not in seen:
                add(p, "tcp", s.get("service",""), s.get("detected",""))
        # Plain strings in services[] are just notes — skip them

    for note in scan_obj.get("insecure_protocols") or []:
        # Handle both plain strings ("ftp", "rdp") and full sentences
        if not isinstance(note, str):
            continue
        note_lower = note.lower().strip()
        for key,(dport,svc,prod) in INSECURE_PORT_MAP.items():
            if key in note_lower:
                pm = _re.search(r'port\s+(\d+)', note, _re.IGNORECASE)
                add(int(pm.group(1)) if pm else dport, "tcp", svc, prod)

    return {"host":host,"hostname":hostname,"host_status":host_status,"os":os_clean,"ports":ports}


# ── API Endpoints ─────────────────────────────────────────────────────────────

@router.post("/import")
async def import_hosts(request: Request):
    """
    Import JSON scan report (array of hosts).
    Runs full vulnerability analysis on each host and saves to DB.
    Returns the host list immediately.
    """
    db = get_db()
    try:
        body = await request.json()
        items = body if isinstance(body, list) else [body]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}")

    saved = []
    for scan_obj in items:
        try:
            # Map to internal format and run analysis
            mapped      = _map_json_scan(scan_obj)
            analysis    = await _scanner.analyze_scan(mapped)

            device_type  = _detect_device_type(scan_obj)
            criticality  = _detect_criticality(analysis)
            status       = _detect_status(scan_obj)
            detected     = _get_detected_info(scan_obj)
            host_ip      = mapped["host"]
            hostname     = mapped.get("hostname") or scan_obj.get("hostname") or host_ip
            os_info      = mapped["os"]

            # Build host record
            host_id = str(uuid.uuid4())
            host_record = {
                "host_id":     host_id,
                "host":        host_ip,
                "hostname":    hostname,
                "os":          os_info,
                "status":      status,
                "device_type": device_type,
                "criticality": criticality,
                "detected":    detected,
                "open_ports":  len([p for p in mapped["ports"] if p["state"]=="open"]),
                "total_cves":  analysis.get("total_cves_found", 0),
                "risk_summary":analysis.get("risk_summary", {}),
                "analysis":    analysis,
                "raw_scan":    scan_obj,
                "imported_at": datetime.utcnow().isoformat(),
            }

            # Upsert by IP (replace if same host re-imported)
            await db.scanned_hosts.update_one(
                {"host": host_ip},
                {"$set": host_record},
                upsert=True
            )
            saved.append({
                "host_id":    host_id,
                "host":       host_ip,
                "hostname":   hostname,
                "status":     status,
                "device_type":device_type,
                "criticality":criticality,
                "detected":   detected,
                "open_ports": len([p for p in mapped["ports"] if p["state"]=="open"]),
                "total_cves": analysis.get("total_cves_found", 0),
                "os":         os_info,
            })
        except Exception as e:
            logger.error(f"Error processing host {scan_obj.get('host','?')}: {e}")
            saved.append({"host": scan_obj.get("host","unknown"), "error": str(e)})

    return {"imported": len(saved), "hosts": saved}


@router.get("/")
async def list_hosts(
    keyword:     Optional[str] = None,
    criticality: Optional[str] = None,
    device_type: Optional[str] = None,
    status:      Optional[str] = None,
    page:        int = 1,
    page_size:   int = 20,
):
    """List all scanned hosts with filters."""
    db    = get_db()
    query = {}
    if keyword:
        query["$or"] = [
            {"host":       {"$regex": keyword, "$options":"i"}},
            {"hostname":   {"$regex": keyword, "$options":"i"}},
            {"os":         {"$regex": keyword, "$options":"i"}},
            {"device_type":{"$regex": keyword, "$options":"i"}},
        ]
    if criticality: query["criticality"] = criticality.upper()
    if device_type: query["device_type"] = {"$regex": device_type, "$options":"i"}
    if status:      query["status"]      = {"$regex": status, "$options":"i"}

    total  = await db.scanned_hosts.count_documents(query)
    skip   = (page-1) * page_size
    cursor = db.scanned_hosts.find(query, {"_id":0, "analysis":0, "raw_scan":0})\
                              .sort("imported_at", -1).skip(skip).limit(page_size)
    hosts  = [doc async for doc in cursor]
    return {"total": total, "page": page, "page_size": page_size, "hosts": hosts}


@router.get("/{host_id}")
async def get_host_detail(host_id: str):
    """Get full analysis for a single host."""
    db  = get_db()
    doc = await db.scanned_hosts.find_one(
        {"$or": [{"host_id": host_id}, {"host": host_id}]}, {"_id":0}
    )
    if not doc:
        raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
    return doc


@router.delete("/")
async def clear_hosts():
    """Clear all scanned hosts."""
    db  = get_db()
    res = await db.scanned_hosts.delete_many({})
    return {"deleted": res.deleted_count}
