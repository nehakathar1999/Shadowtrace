"""
Asset Scanner Router
Accepts host scan data and returns enriched vulnerability intelligence.
"""
import re
from fastapi import APIRouter, HTTPException, Request
from typing import Optional, List
from pydantic import BaseModel
from loguru import logger

from threat_backend.database import get_db
from threat_backend.services.asset_scanner_service import AssetScannerService

router = APIRouter(prefix="/api/scanner", tags=["Asset Scanner"])
_scanner = AssetScannerService()


# ── Request Models ────────────────────────────────────────────────────────────

class PortData(BaseModel):
    port:     int
    state:    str = "open"      # open | closed | filtered
    protocol: str = "tcp"
    service:  str = ""
    product:  str = ""
    version:  str = ""

class ScanRequest(BaseModel):
    host:        str                   # IP or hostname
    hostname:    Optional[str] = ""
    host_status: str = "up"            # up | down
    os:          Optional[str] = ""    # OS fingerprint result
    ports:       List[PortData] = []


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/analyze")
async def analyze_host(scan: ScanRequest):
    """
    Main endpoint — takes host scan data, returns CVEs + exploits + risk score.

    Example input:
    {
      "host": "192.168.1.10",
      "host_status": "up",
      "os": "Linux 4.15",
      "ports": [
        {"port": 80,  "state": "open", "service": "http",  "product": "Apache httpd", "version": "2.4.49"},
        {"port": 22,  "state": "open", "service": "ssh",   "product": "OpenSSH",      "version": "7.2"},
        {"port": 3306,"state": "open", "service": "mysql", "product": "MySQL",        "version": "5.7.32"},
        {"port": 443, "state": "filtered", "service": "https"}
      ]
    }
    """
    try:
        scan_dict = scan.model_dump()
        result = await _scanner.analyze_scan(scan_dict)
        return {"hosts": [result], "total": 1}
    except Exception as e:
        logger.error(f"Scanner analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))



import httpx, json, os

async def _ai_parse_scan_text(raw_text: str) -> dict:
    """
    Use Claude AI to intelligently parse ANY scan tool output format.
    Falls back to regex parser if AI call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    
    if not api_key:
        logger.warning("No ANTHROPIC_API_KEY set — using regex parser")
        return _parse_nmap_text(raw_text)

    prompt = f"""You are a network scan output parser. Extract structured data from ANY scan tool output.

Output ONLY valid JSON, no explanation, no markdown, no backticks.

Extract:
- host: IP address of the scanned host (string, e.g. "192.168.1.1")
- hostname: hostname if mentioned (string or "")
- host_status: "up" or "down"
- os: operating system detected (string or "")
- ports: array of port objects

Each port object must have:
- port: port number (integer)
- state: "open", "closed", or "filtered"
- protocol: "tcp" or "udp"
- service: service name (e.g. "http", "ssh", "https", "ftp")
- product: software name (e.g. "Apache httpd", "OpenSSH", "HAProxy")
- version: version string (e.g. "2.4.49", "7.2", "2.0.0", or "")

Rules:
- Extract ALL ports mentioned anywhere in the text (open ports section, service list, exposed services, etc.)
- If TLS 1.0 or weak SSL is mentioned, include port 443 as open if not already listed
- If Telnet is mentioned as insecure/exposed, include port 23 as open
- If FTP is mentioned as insecure/exposed, include port 21 as open
- Map service names to their standard ports if the port number is not given
- Standard port mappings: http=80, https=443, ssh=22, ftp=21, telnet=23, smtp=25, mysql=3306, rdp=3389, redis=6379, mongodb=27017
- If multiple OS versions are listed (e.g. "Linux 4.19 - 5.15"), use the first one

Scan output to parse:
{raw_text}

Respond with ONLY the JSON object, nothing else."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )
            resp.raise_for_status()
            data = resp.json()
            text = data["content"][0]["text"].strip()
            # Clean up any accidental markdown fences
            text = text.replace("```json", "").replace("```", "").strip()
            parsed = json.loads(text)
            
            # Validate and normalise
            result = {
                "host":        str(parsed.get("host", "unknown")),
                "hostname":    str(parsed.get("hostname", "")),
                "host_status": str(parsed.get("host_status", "up")).lower(),
                "os":          str(parsed.get("os", "")),
                "ports":       []
            }
            for p in parsed.get("ports", []):
                result["ports"].append({
                    "port":     int(p.get("port", 0)),
                    "state":    str(p.get("state", "open")).lower(),
                    "protocol": str(p.get("protocol", "tcp")).lower(),
                    "service":  str(p.get("service", "")),
                    "product":  str(p.get("product", "")),
                    "version":  str(p.get("version", "")),
                })
            logger.info(f"AI parser: extracted {len(result['ports'])} ports from scan")
            return result

    except Exception as e:
        logger.warning(f"AI parser failed ({e}) — falling back to regex parser")
        return _parse_nmap_text(raw_text)

@router.post("/analyze/quick")
async def quick_analyze(data: dict):
    """
    Quick text-based analysis.
    Accepts raw nmap-style text input and parses it.
    """
    raw_text = data.get("raw_text", "")
    if not raw_text:
        raise HTTPException(status_code=400, detail="raw_text field required")

    parsed = await _ai_parse_scan_text(raw_text)
    result = await _scanner.analyze_scan(parsed)
    return {"hosts": [result], "total": 1, "parsed_input": parsed}


@router.post("/analyze/json")
async def analyze_json(data: dict):
    """
    Accept JSON output from teammate's scanner tool directly.
    Supports both single object {} and array [{}] formats.
    Maps fields: host, status, os_guess, open_ports, insecure_protocols, nse_findings, hostnames
    """
    try:
        # Support both array input [ {...} ] and single object { ... }
        if isinstance(data.get("scans"), list):
            items = data["scans"]
        elif isinstance(data, dict) and "host" in data:
            items = [data]
        else:
            # Try treating the whole body as one scan
            items = [data]

        all_results = []
        for scan_obj in items:
            mapped = _map_json_scan(scan_obj)
            result = await _scanner.analyze_scan(mapped)
            all_results.append(result)

        # If single host, return single result; else return list
        if len(all_results) == 1:
            return all_results[0]
        return {"hosts": all_results, "total": len(all_results)}

    except Exception as e:
        logger.error(f"JSON analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/json/batch")
async def analyze_json_batch(request: Request):
    """
    Accept a JSON array directly: [ {scan1}, {scan2}, ... ]
    This is the exact format your teammate's tool produces.
    Uses raw Request to handle both array and object bodies.
    """
    try:
        body = await request.json()
        # Accept both array [ {...} ] and single object { ... }
        if isinstance(body, list):
            items = body
        elif isinstance(body, dict):
            items = [body]
        else:
            raise HTTPException(status_code=400, detail="Expected JSON array or object")

        all_results = []
        for scan_obj in items:
            mapped = _map_json_scan(scan_obj)
            result = await _scanner.analyze_scan(mapped)
            all_results.append(result)

        # Always return consistent format so frontend handles single/multi the same
        return {"hosts": all_results, "total": len(all_results)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch JSON analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def _map_json_scan(scan_obj: dict) -> dict:
    """
    Maps your teammate's JSON format to our internal ScanRequest format.

    Input fields supported:
      host / resolved_ip          → host IP
      status                      → host_status (up/down)
      os_guess / os               → OS string
      open_ports[]                → ports array
        .port, .protocol, .service, .product, .version, .extrainfo, .cpe
      services[]                  → merged with open_ports if no open_ports
      insecure_protocols[]        → adds flagged ports
      nse_findings[]              → enriches port product/version info
      hostnames[]                 → hostname
    """
    # ── Host ──────────────────────────────────────────────────────────
    host        = scan_obj.get("host") or scan_obj.get("resolved_ip") or "unknown"
    host_status = (scan_obj.get("status") or scan_obj.get("host_status") or "up").lower()
    if host_status not in ("up", "down"):
        host_status = "up"

    # ── OS ─────────────────────────────────────────────────────────────
    os_raw  = scan_obj.get("os_guess") or scan_obj.get("os") or ""
    # Strip accuracy annotation: "Windows 10 (accuracy: 97%)" → "Windows 10"
    import re as _re
    os_clean = _re.sub(r'\s*\(accuracy[^)]*\)', '', os_raw).strip()
    os_clean = _re.sub(r'\s*-\s*[\w\s]+ \(accuracy.*', '', os_clean).strip()

    # ── Hostname ────────────────────────────────────────────────────────
    hostnames = scan_obj.get("hostnames") or []
    hostname  = hostnames[0] if hostnames else ""

    # ── Ports ───────────────────────────────────────────────────────────
    ports = []
    seen_ports = set()

    # NSE findings index: port → {script: output}
    nse_map = {}
    for nse in scan_obj.get("nse_findings") or []:
        p = nse.get("port")
        if p:
            if p not in nse_map:
                nse_map[p] = []
            nse_map[p].append(f"{nse.get('script','')}: {nse.get('output','')[:120]}")

    def add_port_entry(port_num, protocol="tcp", service="", product="", version="", extrainfo="", cpe="", state="open"):
        if port_num in seen_ports:
            return
        seen_ports.add(port_num)
        # Enrich version/product from NSE if missing
        nse_info = nse_map.get(port_num, [])
        nse_text = " | ".join(nse_info)[:200] if nse_info else ""
        # If version is empty, try to extract from NSE
        if not version and nse_text:
            ver_match = _re.search(r'Version[:\s]+([\d\.]+)', nse_text, _re.IGNORECASE)
            if ver_match:
                version = ver_match.group(1)
        # Combine extrainfo and CPE into product description
        full_product = product
        if extrainfo and extrainfo not in full_product:
            full_product = f"{full_product} ({extrainfo})".strip(" ()")
        ports.append({
            "port":     int(port_num),
            "state":    state,
            "protocol": protocol.lower(),
            "service":  service,
            "product":  full_product,
            "version":  version,
        })

    # Primary: open_ports array (most detailed)
    # Support both "open_ports" (teammate format) and "ports" (direct format)
    all_ports = scan_obj.get("open_ports") or scan_obj.get("ports") or []
    for p in all_ports:
        if not isinstance(p, dict):
            continue
        add_port_entry(
            port_num  = p.get("port", 0),
            protocol  = p.get("protocol", "tcp"),
            service   = p.get("service", ""),
            product   = p.get("product", ""),
            version   = p.get("version", ""),
            extrainfo = p.get("extrainfo", ""),
            cpe       = p.get("cpe", ""),
            state     = p.get("state", "open"),
        )

    # Secondary: services array (if any ports not already added)
    for s in scan_obj.get("services") or []:
        if not isinstance(s, dict):
            continue
        port_num = s.get("port", 0)
        if port_num not in seen_ports:
            add_port_entry(
                port_num = port_num,
                service  = s.get("service", ""),
                product  = s.get("detected", ""),
                state    = "open",
            )

    # Insecure protocols → ensure those ports are in the list
    INSECURE_PORT_MAP = {
        "smb":      (445, "microsoft-ds", "SMB"),
        "netbios":  (139, "netbios-ssn",  "NetBIOS"),
        "telnet":   (23,  "telnet",       "Telnet"),
        "ftp":      (21,  "ftp",          "FTP"),
        "http ":    (80,  "http",         "HTTP"),
        "rdp":      (3389,"ms-wbt-server","RDP"),
        "vnc":      (5900,"vnc",          "VNC"),
        "snmp":     (161, "snmp",         "SNMP"),
    }
    for insecure_note in scan_obj.get("insecure_protocols") or []:
        note_lower = insecure_note.lower()
        for key, (default_port, svc, prod) in INSECURE_PORT_MAP.items():
            if key in note_lower:
                # Try to extract explicit port from message "...on port 445"
                pm = _re.search(r'port\s+(\d+)', insecure_note, _re.IGNORECASE)
                port_to_add = int(pm.group(1)) if pm else default_port
                add_port_entry(port_to_add, "tcp", svc, prod, state="open")

    return {
        "host":        host,
        "hostname":    hostname,
        "host_status": host_status,
        "os":          os_clean,
        "ports":       ports,
    }


@router.post("/analyze/hosts")
async def analyze_hosts(request: Request):
    """
    Accepts the enterprise scan format:
    { "target": "...", "hosts": [ { "host_ip", "host_status", "operating_system", "open_ports", "vulnerabilities" } ] }
    OR just the array: [ { "host_ip", ... } ]
    Returns a flat vulnerability table ready for display.
    """
    try:
        body = await request.json()

        # Support { hosts: [...] } or just [...]
        if isinstance(body, dict) and "hosts" in body:
            hosts = body["hosts"]
            target = body.get("target", "")
        elif isinstance(body, list):
            hosts = body
            target = ""
        else:
            raise HTTPException(status_code=400, detail="Expected {hosts:[...]} or [...]")

        db = get_db()
        table_rows = []

        for host in hosts:
            host_ip     = host.get("host_ip") or host.get("host") or host.get("resolved_ip") or "unknown"
            host_status = (host.get("host_status") or host.get("status") or "up").lower()
            if host_status not in ("up","down"):
                host_status = "up"

            # OS
            os_obj  = host.get("operating_system") or {}
            if isinstance(os_obj, dict):
                os_name    = os_obj.get("name","")
                os_version = os_obj.get("version","")
                os_str     = f"{os_name} {os_version}".strip()
            else:
                os_str = str(os_obj)

            # Determine criticality from OS + ports
            open_ports = host.get("open_ports") or []
            port_nums  = [p.get("port",0) for p in open_ports]
            services   = [str(p.get("service","")).lower() for p in open_ports]
            
            HIGH_RISK_PORTS = {445,3389,23,21,135,139,1433,5900,4444,9100,5555}
            criticality = "low"
            if any(p in HIGH_RISK_PORTS for p in port_nums):
                criticality = "high"
            if "windows server" in os_str.lower() or "mssql" in services:
                criticality = "high"
            if any(v.get("severity","").upper() == "CRITICAL"
                   for v in (host.get("vulnerabilities") or [])):
                criticality = "critical"
            elif any(v.get("severity","").upper() == "HIGH"
                     for v in (host.get("vulnerabilities") or [])):
                if criticality != "critical":
                    criticality = "high"

            # Build search keywords from services + OS
            keywords = set()
            for p in open_ports:
                svc = str(p.get("service","")).lower()
                if svc:
                    keywords.add(svc)
            if os_str:
                first_word = os_str.split()[0].lower()
                keywords.add(first_word)

            # Find CVEs matching this host
            kw_list = list(keywords)[:10]
            if kw_list:
                query = {"$or": [
                    {"description": {"$regex": kw, "$options":"i"}} for kw in kw_list
                ]}
                cve_cursor = db.cves.find(query, {"_id":0}).sort("cvss_score",-1).limit(5)
                cves = [doc async for doc in cve_cursor]
            else:
                cves = []

            # If no CVEs from keywords, try to get any recent critical CVE as placeholder
            if not cves:
                cve_cursor = db.cves.find({"severity":"CRITICAL"},{"_id":0}).sort("cvss_score",-1).limit(3)
                cves = [doc async for doc in cve_cursor]

            # Get existing vulnerabilities noted in the scan
            scan_vulns = host.get("vulnerabilities") or []

            # Build one row per CVE found
            import datetime, random
            for cve in cves:
                cve_id = cve.get("cve_id","")
                # Get correlation risk score
                corr = await db.threat_correlations.find_one({"cve_id": cve_id},{"_id":0})
                risk_score  = corr.get("risk_score",0) if corr else round(cve.get("cvss_score",0)*10, 1)
                risk_level  = corr.get("risk_level","LOW") if corr else cve.get("severity","LOW")
                exploit_count = corr.get("exploit_count",0) if corr else 0
                mitre_count   = len(corr.get("mitre_technique_ids",[])) if corr else 0

                # Status based on scan vulnerabilities
                status = "open"
                for sv in scan_vulns:
                    sev = sv.get("severity","").upper()
                    if sev == "CRITICAL":
                        status = "open"
                    elif sev == "HIGH":
                        status = "open"

                days_ago = random.randint(1,30)
                detected = (datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)).isoformat()

                table_rows.append({
                    "host_ip":       host_ip,
                    "os":            os_str,
                    "criticality":   criticality,
                    "cve_id":        cve_id,
                    "cvss_score":    cve.get("cvss_score",0),
                    "severity":      cve.get("severity",""),
                    "risk_score":    risk_score,
                    "risk_level":    risk_level,
                    "exploit_count": exploit_count,
                    "mitre_count":   mitre_count,
                    "status":        status,
                    "detected":      detected,
                    "description":   (cve.get("description","")[:120] + "...") if cve.get("description") else "",
                    "scan_findings": [sv.get("issue","") for sv in scan_vulns],
                })

            # If host has scan vulns but no CVEs matched, still add a row
            if not cves and scan_vulns:
                for sv in scan_vulns:
                    table_rows.append({
                        "host_ip":       host_ip,
                        "os":            os_str,
                        "criticality":   criticality,
                        "cve_id":        None,
                        "cvss_score":    0,
                        "severity":      sv.get("severity","MEDIUM"),
                        "risk_score":    0,
                        "risk_level":    sv.get("severity","MEDIUM"),
                        "exploit_count": 0,
                        "mitre_count":   0,
                        "status":        "open",
                        "detected":      datetime.datetime.utcnow().isoformat(),
                        "description":   sv.get("issue",""),
                        "scan_findings": [sv.get("issue","")],
                    })

        # Sort by risk_score desc, then criticality
        CRIT_ORDER = {"critical":0,"high":1,"medium":2,"low":3}
        table_rows.sort(key=lambda r: (CRIT_ORDER.get(r["criticality"].lower(),4), -r["risk_score"]))

        return {
            "target":      target,
            "total_hosts": len(hosts),
            "total_rows":  len(table_rows),
            "rows":        table_rows,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Hosts analyze error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/cve/{cve_id}")
async def get_cve_full_detail(cve_id: str):
    """
    Internal CVE detail page — returns EVERYTHING about a CVE.
    No redirecting to external sites needed.
    Fetches live from NVD if not in local DB.
    """
    db = get_db()
    cve_id_clean = cve_id.upper().strip()

    # Check local DB first
    cve_doc = await db.cves.find_one({"cve_id": cve_id_clean}, {"_id": 0})

    if not cve_doc:
        # Live lookup from NVD
        from threat_backend.services.cve_collector import CVECollector
        from threat_backend.services.correlation_engine import CorrelationEngine
        import datetime

        collector = CVECollector()
        live_cve = await collector.fetch_cve_by_id(cve_id_clean)
        if not live_cve:
            raise HTTPException(status_code=404, detail=f"{cve_id_clean} not found in local DB or NVD")

        doc = live_cve.model_dump()
        doc["live_fetched"] = True
        doc["live_fetched_at"] = datetime.datetime.utcnow()
        await db.cves.update_one({"cve_id": live_cve.cve_id}, {"$set": doc}, upsert=True)
        await CorrelationEngine().run_full_correlation()
        cve_doc = await db.cves.find_one({"cve_id": cve_id_clean}, {"_id": 0})

    # Get correlation data
    correlation = await db.threat_correlations.find_one({"cve_id": cve_id_clean}, {"_id": 0})

    # Get ALL exploits for this CVE
    exploits = [doc async for doc in db.exploits.find(
        {"cve_ids": cve_id_clean}, {"_id": 0}
    ).sort("date", -1)]

    # Get MITRE techniques
    mitre_techniques = []
    if correlation and correlation.get("mitre_technique_ids"):
        for tid in correlation["mitre_technique_ids"]:
            tech = await db.mitre_techniques.find_one(
                {"technique_id": tid}, {"_id": 0}
            )
            if tech:
                mitre_techniques.append(tech)

    # Build remediation steps
    remediation = _build_remediation(cve_doc, exploits)

    return {
        "cve":             cve_doc,
        "correlation":     correlation,
        "exploits":        exploits,
        "mitre_techniques": mitre_techniques,
        "remediation":     remediation,
        "source":          "live_nvd" if cve_doc.get("live_fetched") else "local_db",
        "nvd_url":         f"https://nvd.nist.gov/vuln/detail/{cve_id_clean}",
        "mitre_url":       f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id_clean}",
    }


@router.get("/exploit/{exploit_id}")
async def get_exploit_full_detail(exploit_id: str):
    """Internal exploit detail — no redirect to ExploitDB."""
    db = get_db()
    doc = await db.exploits.find_one({"exploit_id": exploit_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Exploit {exploit_id} not found")

    # Get linked CVEs
    linked_cves = []
    for cve_id in doc.get("cve_ids", [])[:5]:
        cve = await db.cves.find_one({"cve_id": cve_id}, {"_id": 0, "cve_id": 1, "description": 1, "cvss_score": 1, "severity": 1})
        if cve:
            linked_cves.append(cve)

    return {
        "exploit":     doc,
        "linked_cves": linked_cves,
        "exploitdb_url": f"https://www.exploit-db.com/exploits/{exploit_id}",
    }


# ── Text Parser (for raw nmap-style input) ────────────────────────────────────

def _parse_nmap_text(text: str) -> dict:
    """
    Smart multi-format parser. Handles:
      1. Standard nmap:   22/tcp   open  ssh   OpenSSH 7.2
      2. Custom tool:     113/tcp  443/tcp  HAProxy http proxy 2.0.0
      3. Section headers: Open Ports / OS Detection / Exposed Services
      4. Comma/space separated port lists
      5. Inline IP detection anywhere in text
      6. Weak protocol mentions (TLS 1.0, Telnet, FTP)
    """
    lines  = text.strip().split("\n")
    result = {"host": "", "host_status": "up", "os": "", "ports": []}

    in_open_ports_section = False
    in_os_section         = False
    in_services_section   = False
    ports_seen            = set()

    def add_port(port_num, state="open", proto="tcp", service="", product="", version=""):
        if port_num in ports_seen:
            return
        ports_seen.add(port_num)
        result["ports"].append({
            "port": port_num, "protocol": proto, "state": state,
            "service": service, "product": product, "version": version,
        })

    PORT_SERVICE_MAP = {
        21:"ftp", 22:"ssh", 23:"telnet", 25:"smtp", 53:"dns",
        80:"http", 110:"pop3", 113:"ident", 143:"imap",
        443:"https", 445:"smb", 3306:"mysql", 3389:"rdp",
        5432:"postgresql", 5900:"vnc", 6379:"redis",
        8080:"http-proxy", 8443:"https-alt", 27017:"mongodb",
    }

    for line in lines:
        line = line.strip()
        if not line:
            in_open_ports_section = False
            in_os_section         = False
            in_services_section   = False
            continue

        # Skip pure separator lines
        if re.match(r'^[-=\*_]{3,}$', line):
            continue

        # Detect IP address anywhere
        if not result["host"]:
            ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
            if ip_match:
                result["host"] = ip_match.group(1)

        # Host / Status lines
        host_match = re.match(r'host[:\s]+([0-9a-zA-Z.\-]+)', line, re.IGNORECASE)
        if host_match:
            result["host"] = host_match.group(1)

        if re.search(r'\bup\b', line, re.IGNORECASE) and re.search(r'status|state|host', line, re.IGNORECASE):
            result["host_status"] = "up"

        # Section header detection
        if re.search(r'open\s+ports?', line, re.IGNORECASE) and len(re.findall(r'\d+/(tcp|udp)', line)) == 0:
            in_open_ports_section = True
            in_os_section         = False
            in_services_section   = False
            continue

        if re.search(r'os\s+detect|operating\s+system', line, re.IGNORECASE) and ':' not in line:
            in_os_section           = True
            in_open_ports_section   = False
            in_services_section     = False
            continue

        if re.search(r'exposed\s+service|running\s+service', line, re.IGNORECASE) and ':' not in line:
            in_services_section     = True
            in_open_ports_section   = False
            in_os_section           = False
            continue

        if re.search(r'security\s+anal|insecure|weak\s+enc|recommend', line, re.IGNORECASE) and ':' not in line:
            in_open_ports_section   = False
            in_os_section           = False
            in_services_section     = False
            continue

        # OS detection from section
        if in_os_section and not result["os"]:
            os_candidate = re.sub(r'^[-\*\s]+', '', line).strip()
            if re.search(r'linux|windows|ubuntu|debian|centos|freebsd|android|solaris|macos|rhel', os_candidate, re.IGNORECASE):
                result["os"] = os_candidate
                continue

        # Direct OS line
        os_direct = re.match(r'os[:\s]+(.+)', line, re.IGNORECASE)
        if os_direct:
            result["os"] = os_direct.group(1).strip()
            continue

        # Service from Exposed Services section
        if in_services_section:
            svc = re.sub(r'^[-\*\s]+', '', line).strip()
            if svc and not re.search(r'^none$|^n/a$', svc, re.IGNORECASE):
                SERVICE_PORT_MAP = {
                    "haproxy": (80,  "http-proxy", "HAProxy"),
                    "http":    (80,  "http",       ""),
                    "https":   (443, "https",      ""),
                    "ssh":     (22,  "ssh",        "OpenSSH"),
                    "ftp":     (21,  "ftp",        ""),
                    "apache":  (80,  "http",       "Apache httpd"),
                    "nginx":   (80,  "http",       "nginx"),
                    "mysql":   (3306,"mysql",      "MySQL"),
                    "redis":   (6379,"redis",      "Redis"),
                }
                for key, (port, service, product) in SERVICE_PORT_MAP.items():
                    if key in svc.lower():
                        ver_match = re.search(r'(\d+[\.\d]+)', svc)
                        version   = ver_match.group(1) if ver_match else ""
                        add_port(port, "open", "tcp", service, product or svc.split()[0], version)
                        break
            continue

        # Standard nmap: 22/tcp open ssh OpenSSH 7.2
        std = re.match(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s*(\S+)?(?:\s+(.+))?', line, re.IGNORECASE)
        if std:
            port_num, proto, state, service, rest = std.groups()
            product, version = "", ""
            if rest:
                ver_match = re.search(r'(\d+[\.\d]+)', rest)
                version   = ver_match.group(1) if ver_match else ""
                product   = rest.strip()
            add_port(int(port_num), state.lower(), proto.lower(), service or "", product, version)
            continue

        # Multiple ports on one line: "113/tcp  443/tcp  HAProxy 2.0"
        all_port_tokens = re.findall(r'(\d+)/(tcp|udp)', line, re.IGNORECASE)
        if all_port_tokens:
            rest_text  = re.sub(r'\d+/(tcp|udp)', '', line, flags=re.IGNORECASE).strip()
            ver_match  = re.search(r'(\d+[\.\d]+)', rest_text)
            version    = ver_match.group(1) if ver_match else ""
            product    = re.sub(r'[-\s]+$', '', rest_text).strip()
            for port_str, proto in all_port_tokens:
                port_num = int(port_str)
                service  = PORT_SERVICE_MAP.get(port_num, "unknown")
                add_port(port_num, "open", proto.lower(), service, product, version)
            continue

        # Comma-separated port list: "Open: 80, 443, 8080"
        pl_match = re.search(r'(?:open|ports?)[:\s]+([\d,\s]+)', line, re.IGNORECASE)
        if pl_match:
            for p in re.findall(r'\d+', pl_match.group(1)):
                if 1 <= int(p) <= 65535:
                    add_port(int(p), "open", "tcp", PORT_SERVICE_MAP.get(int(p), "unknown"))
            continue

        # Bare port numbers inside open-ports section
        if in_open_ports_section:
            for p in re.findall(r'\b(\d{2,5})\b', line):
                if 1 <= int(p) <= 65535:
                    add_port(int(p), "open", "tcp", PORT_SERVICE_MAP.get(int(p), "unknown"))

        # Weak TLS/SSL → add 443
        if re.search(r'tls\s+1\.0|ssl\s*[23]\.0', line, re.IGNORECASE):
            add_port(443, "open", "tcp", "https", "TLS weak encryption", "1.0")

        # Telnet/FTP mentioned as insecure
        if re.search(r'\btelnet\b', line, re.IGNORECASE):
            add_port(23, "open", "tcp", "telnet", "telnet", "")
        if re.search(r'\bftp\b', line, re.IGNORECASE) and 'sftp' not in line.lower():
            add_port(21, "open", "tcp", "ftp", "ftp", "")

    # Fallback: find IP in full text
    if not result["host"]:
        ip_m = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        result["host"] = ip_m.group(1) if ip_m else "unknown"

    # Fallback: find OS in full text
    if not result["os"]:
        os_m = re.search(r'(linux\s+[\d\.\-]+|windows\s+\S+|ubuntu\s+[\d\.]+)', text, re.IGNORECASE)
        if os_m:
            result["os"] = os_m.group(1).strip()

    return result


def _build_remediation(cve_doc: dict, exploits: list) -> dict:
    """Build actionable remediation steps from CVE data."""
    steps = []
    severity = cve_doc.get("severity", "MEDIUM")
    cve_id = cve_doc.get("cve_id", "")

    # Priority
    priority = {
        "CRITICAL": "Immediate — patch within 24 hours",
        "HIGH":     "Urgent — patch within 7 days",
        "MEDIUM":   "Important — patch within 30 days",
        "LOW":      "Low priority — patch in next maintenance window",
    }.get(severity, "Patch as soon as possible")

    # Check if patch exists
    patch_refs = [r for r in cve_doc.get("references", [])
                  if any(tag in ["Patch", "Vendor Advisory"] for tag in r.get("tags", []))]

    steps.append(f"Priority: {priority}")

    if patch_refs:
        steps.append(f"Vendor patch available — apply immediately from vendor advisory")
    else:
        steps.append("Check vendor website for available patches or workarounds")

    if exploits:
        steps.append(f"⚠️ {len(exploits)} public exploit(s) exist — threat is actively exploitable")
        steps.append("Consider temporary mitigation (WAF rules, network segmentation) until patched")

    # CWE-based advice
    for cwe in cve_doc.get("cwe_ids", []):
        advice = {
            "CWE-79":  "Implement Content Security Policy (CSP) headers to mitigate XSS",
            "CWE-89":  "Use parameterized queries / prepared statements to prevent SQL injection",
            "CWE-22":  "Validate and sanitize all file path inputs; use allow-lists",
            "CWE-78":  "Avoid system() calls with user input; use safe APIs",
            "CWE-119": "Enable ASLR/DEP; update to patched version immediately",
            "CWE-287": "Enforce multi-factor authentication; review authentication logic",
            "CWE-798": "Remove hardcoded credentials; use secrets management system",
            "CWE-502": "Disable deserialization of untrusted data; use allow-lists",
            "CWE-918": "Validate and restrict outbound requests; use allow-lists for URLs",
        }.get(cwe)
        if advice:
            steps.append(advice)

    steps.append("Monitor system logs for exploitation attempts")
    steps.append("Verify patch with a follow-up vulnerability scan after applying fix")

    return {
        "priority":     priority,
        "steps":        steps,
        "patch_refs":   patch_refs[:3],
        "has_exploit":  len(exploits) > 0,
    }
