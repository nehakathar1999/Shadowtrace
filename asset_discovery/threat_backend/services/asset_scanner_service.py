"""
Asset Scanner Service
Takes host scan data (ports, services, OS) and finds matching CVEs/exploits.
This is what ties the vulnerability scanner team's nmap-style output
to our threat intelligence database.
"""
from typing import List, Optional, Dict
from loguru import logger
from threat_backend.database import get_db
from threat_backend.services.cve_collector import CVECollector

# ── Common service → CVE keyword mappings ────────────────────────────────────
SERVICE_CVE_KEYWORDS = {
    "apache":       ["apache", "httpd"],
    "httpd":        ["apache", "httpd"],
    "nginx":        ["nginx"],
    "iis":          ["iis", "microsoft iis"],
    "openssh":      ["openssh", "ssh"],
    "ssh":          ["openssh", "ssh"],
    "mysql":        ["mysql"],
    "mariadb":      ["mariadb", "mysql"],
    "postgresql":   ["postgresql", "postgres"],
    "mssql":        ["sql server", "mssql"],
    "mongodb":      ["mongodb"],
    "redis":        ["redis"],
    "ftp":          ["ftp", "vsftpd", "proftpd"],
    "vsftpd":       ["vsftpd"],
    "samba":        ["samba", "smb"],
    "smb":          ["samba", "smb"],
    "rdp":          ["remote desktop", "rdp"],
    "vnc":          ["vnc"],
    "telnet":       ["telnet"],
    "smtp":         ["smtp", "sendmail", "postfix", "exim"],
    "sendmail":     ["sendmail"],
    "postfix":      ["postfix"],
    "exim":         ["exim"],
    "bind":         ["bind", "named", "dns"],
    "named":        ["bind", "named"],
    "tomcat":       ["tomcat", "apache tomcat"],
    "jboss":        ["jboss", "wildfly"],
    "weblogic":     ["weblogic", "oracle weblogic"],
    "websphere":    ["websphere"],
    "php":          ["php"],
    "wordpress":    ["wordpress"],
    "drupal":       ["drupal"],
    "joomla":       ["joomla"],
    "jenkins":      ["jenkins"],
    "docker":       ["docker"],
    "kubernetes":   ["kubernetes", "k8s"],
    "elasticsearch":["elasticsearch"],
    "log4j":        ["log4j", "log4shell"],
    "openssl":      ["openssl"],
    "ssl":          ["openssl", "ssl", "tls"],
    "tls":          ["openssl", "ssl", "tls"],
    "snmp":         ["snmp"],
    "ntp":          ["ntp"],
    "ldap":         ["ldap", "openldap"],
    "kerberos":     ["kerberos"],
}

OS_CVE_KEYWORDS = {
    "windows":      ["windows"],
    "linux":        ["linux", "kernel"],
    "ubuntu":       ["ubuntu"],
    "debian":       ["debian"],
    "centos":       ["centos", "rhel", "red hat"],
    "rhel":         ["red hat", "rhel"],
    "fedora":       ["fedora"],
    "macos":        ["macos", "mac os", "apple mac"],
    "android":      ["android"],
    "ios":          ["ios", "iphone", "ipad"],
    "freebsd":      ["freebsd"],
    "solaris":      ["solaris", "oracle solaris"],
}

# Common high-risk ports
HIGH_RISK_PORTS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    111:  "rpcbind",
    135:  "msrpc",
    139:  "netbios",
    143:  "imap",
    443:  "https",
    445:  "smb",
    512:  "rexec",
    513:  "rlogin",
    514:  "rsh",
    873:  "rsync",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    4444: "metasploit",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    9200: "elasticsearch",
    27017:"mongodb",
}


class AssetScannerService:

    async def analyze_scan(self, scan_data: dict) -> dict:
        """
        Main entry point.
        Takes nmap-style scan data and returns enriched threat intelligence.
        """
        db = get_db()

        host        = scan_data.get("host", "unknown")
        host_status = scan_data.get("host_status", "up")
        ports       = scan_data.get("ports", [])       # list of port objects
        os_info     = scan_data.get("os", "")
        hostname    = scan_data.get("hostname", "")

        if host_status.lower() != "up":
            return {
                "host": host,
                "host_status": host_status,
                "message": "Host is down or unreachable. No scan results.",
                "vulnerabilities": [],
                "risk_summary": {},
            }

        # Extract keywords from services and OS
        search_keywords = self._extract_keywords(ports, os_info)
        risk_ports      = self._identify_risky_ports(ports)

        # Find matching CVEs
        cve_results = await self._find_matching_cves(db, search_keywords, ports)

        # Enrich with exploits and correlations
        enriched = await self._enrich_results(db, cve_results)

        # Build risk summary
        risk_summary = self._build_risk_summary(enriched, risk_ports, ports)

        # Build service analysis
        service_analysis = self._analyze_services(ports)

        return {
            "host":             host,
            "hostname":         hostname,
            "host_status":      host_status,
            "os_detected":      os_info,
            "total_open_ports": len([p for p in ports if p.get("state") == "open"]),
            "risk_ports":       risk_ports,
            "service_analysis": service_analysis,
            "search_keywords":  search_keywords,
            "total_cves_found": len(enriched),
            "vulnerabilities":  enriched,
            "risk_summary":     risk_summary,
        }

    def _extract_keywords(self, ports: list, os_info: str) -> List[str]:
        """Extract CVE search keywords from service names and OS."""
        keywords = set()

        # From services on open ports
        for port in ports:
            if port.get("state") != "open":
                continue
            service = (port.get("service", "") or "").lower()
            version = (port.get("version", "") or "").lower()
            product = (port.get("product", "") or "").lower()

            # Direct service match
            for svc_key, kw_list in SERVICE_CVE_KEYWORDS.items():
                if svc_key in service or svc_key in product:
                    keywords.update(kw_list)

            # Version-based keywords (e.g. "Apache httpd 2.2")
            if product:
                keywords.add(product.split()[0])  # first word of product name

        # From OS fingerprinting
        if os_info:
            os_lower = os_info.lower()
            for os_key, kw_list in OS_CVE_KEYWORDS.items():
                if os_key in os_lower:
                    keywords.update(kw_list)

        return list(keywords)[:20]  # cap at 20 keywords

    def _identify_risky_ports(self, ports: list) -> list:
        """Flag ports that are commonly exploited."""
        risky = []
        for port in ports:
            if port.get("state") != "open":
                continue
            port_num = int(port.get("port", 0))
            if port_num in HIGH_RISK_PORTS:
                risky.append({
                    "port":    port_num,
                    "service": port.get("service") or HIGH_RISK_PORTS[port_num],
                    "risk":    "HIGH" if port_num in [23, 445, 135, 139, 512, 513, 514, 4444] else "MEDIUM",
                    "reason":  self._port_risk_reason(port_num),
                })
        return risky

    def _port_risk_reason(self, port: int) -> str:
        reasons = {
            23:   "Telnet transmits credentials in plaintext",
            445:  "SMB — commonly exploited by ransomware (WannaCry, NotPetya)",
            135:  "MS-RPC — used in many Windows exploits",
            139:  "NetBIOS — information disclosure risk",
            21:   "FTP — credentials often transmitted in plaintext",
            3389: "RDP — brute-force and BlueKeep attacks",
            5900: "VNC — often misconfigured with weak passwords",
            4444: "Default Metasploit listener port",
            6379: "Redis — often exposed without authentication",
            27017:"MongoDB — often exposed without authentication",
            9200: "Elasticsearch — often exposed without authentication",
            2049: "NFS — file system exposure risk",
            512:  "rexec — remote execution without strong auth",
        }
        return reasons.get(port, "Commonly targeted by attackers")

    def _analyze_services(self, ports: list) -> list:
        """Build service analysis with risk assessment."""
        services = []
        for port in ports:
            port_num = int(port.get("port", 0))
            state    = port.get("state", "unknown")
            service  = port.get("service", "unknown")
            version  = port.get("version", "")
            product  = port.get("product", "")

            risk = "LOW"
            if state == "open":
                if port_num in [23, 445, 135, 139, 512, 513, 514, 4444]:
                    risk = "CRITICAL"
                elif port_num in [21, 3389, 5900, 6379, 27017, 9200]:
                    risk = "HIGH"
                elif port_num in HIGH_RISK_PORTS:
                    risk = "MEDIUM"

            services.append({
                "port":        port_num,
                "state":       state,
                "service":     service,
                "product":     product,
                "version":     version,
                "risk":        risk,
                "is_filtered": state == "filtered",
                "note":        self._service_note(state, port_num, service),
            })
        return sorted(services, key=lambda x: (x["state"] != "open", x["port"]))

    def _service_note(self, state: str, port: int, service: str) -> str:
        if state == "filtered":
            return "Blocked by firewall — service may exist but is not reachable"
        if state == "closed":
            return "Port reachable but no service listening"
        if state == "open":
            if port == 22:
                return "Ensure key-based auth only; disable root login and password auth"
            if port == 80:
                return "HTTP — ensure redirect to HTTPS is configured"
            if port == 443:
                return "HTTPS — check certificate validity and TLS version"
            if port == 3306:
                return "MySQL — should not be exposed to internet"
            if port == 5432:
                return "PostgreSQL — should not be exposed to internet"
        return ""

    async def _find_matching_cves(self, db, keywords: list, ports: list) -> list:
        """Search local CVE DB for vulnerabilities matching discovered services."""
        if not keywords:
            return []

        # Build search query
        keyword_regex_list = [{"description": {"$regex": kw, "$options": "i"}} for kw in keywords]
        product_regex_list = []

        for port in ports:
            if port.get("state") != "open":
                continue
            product = port.get("product", "")
            version = port.get("version", "")
            if product:
                product_regex_list.append({
                    "affected_products.product": {"$regex": product.split()[0], "$options": "i"}
                })

        query = {"$or": keyword_regex_list + product_regex_list}

        cursor = db.cves.find(query, {"_id": 0}).sort("cvss_score", -1).limit(50)
        return [doc async for doc in cursor]

    async def _enrich_results(self, db, cves: list) -> list:
        """Add exploit and correlation data to each CVE."""
        enriched = []
        for cve in cves:
            cve_id = cve.get("cve_id")

            # Get correlation (risk score)
            corr = await db.threat_correlations.find_one(
                {"cve_id": cve_id}, {"_id": 0}
            )

            # Get exploits
            exploits = []
            async for exp in db.exploits.find(
                {"cve_ids": cve_id}, {"_id": 0, "exploit_id": 1, "title": 1, "exploit_type": 1, "verified": 1, "platform": 1}
            ).limit(5):
                exploits.append(exp)

            enriched.append({
                **cve,
                "risk_score":         corr.get("risk_score", 0)        if corr else 0,
                "risk_level":         corr.get("risk_level", "LOW")     if corr else "LOW",
                "exploit_probability":corr.get("exploit_probability", 0) if corr else 0,
                "mitre_techniques":   corr.get("mitre_technique_ids", []) if corr else [],
                "mitre_tactics":      corr.get("mitre_tactic_names", [])  if corr else [],
                "exploits":           exploits,
                "exploit_count":      len(exploits),
            })

        # Sort by risk score descending
        return sorted(enriched, key=lambda x: x.get("risk_score", 0), reverse=True)

    def _build_risk_summary(self, vulnerabilities: list, risk_ports: list, ports: list) -> dict:
        """Build overall risk summary for the host."""
        critical = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
        high     = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
        medium   = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
        low      = sum(1 for v in vulnerabilities if v.get("severity", "").upper() in ["LOW", "NONE"])
        with_exploits = sum(1 for v in vulnerabilities if v.get("exploit_count", 0) > 0)
        open_ports    = len([p for p in ports if p.get("state") == "open"])

        # Overall host risk score
        if critical > 0 or any(p["risk"] == "CRITICAL" for p in risk_ports):
            overall_risk = "CRITICAL"
        elif high > 2 or any(p["risk"] == "HIGH" for p in risk_ports):
            overall_risk = "HIGH"
        elif high > 0 or medium > 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        return {
            "overall_risk":       overall_risk,
            "open_ports":         open_ports,
            "critical_cves":      critical,
            "high_cves":          high,
            "medium_cves":        medium,
            "low_cves":           low,
            "cves_with_exploits": with_exploits,
            "risky_ports_count":  len(risk_ports),
            "top_risk_cve":       vulnerabilities[0].get("cve_id") if vulnerabilities else None,
            "top_risk_score":     vulnerabilities[0].get("risk_score", 0) if vulnerabilities else 0,
            "recommendations": [
                f"Patch {critical} CRITICAL vulnerabilities immediately" if critical > 0 else None,
                f"Close or firewall {len(risk_ports)} high-risk ports" if risk_ports else None,
                f"{with_exploits} vulnerabilities have public exploits — prioritize these" if with_exploits > 0 else None,
                "Run authenticated scan for deeper vulnerability detection",
                "Review service versions and apply latest security patches",
            ]
        }
