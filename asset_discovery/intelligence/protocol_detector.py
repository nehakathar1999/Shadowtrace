INSECURE_PORTS = {
    21: "FTP (unencrypted)",
    23: "Telnet (unencrypted)",
    25: "SMTP (unencrypted)",
    80: "HTTP (unencrypted)",
    110: "POP3 (unencrypted)",
    139: "NetBIOS SSN",
    143: "IMAP (unencrypted)",
    445: "SMB",
    3306: "MySQL",
    8080: "HTTP (unencrypted)"
}


def detect_insecure_protocols(service_list):
    """Returns insecure protocol findings from port/service list."""
    findings = []

    for service in service_list:
        port = service.get("port")
        name = service.get("service") or "unknown"

        if port in INSECURE_PORTS:
            findings.append({
                "port": port,
                "protocol": INSECURE_PORTS[port],
                "message": f"Port {port}: {INSECURE_PORTS[port]} detected",
                "msg": f"{INSECURE_PORTS[port]} detected",
                "service": name
            })

    return findings
