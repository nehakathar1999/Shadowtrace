import ssl, socket

WEAK_TLS_CIPHERS = [
    "TLSv1", "TLSv1.1", "SSLv3", "SSLv2"
]


def analyze_tls(target_host, port=443, timeout=3):
    """Inspect TLS handshake and return whether protocol is weak."""
    findings = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                version = ssock.version() or "unknown"
                cipher = ssock.cipher() or ("unknown", "", "")

                if version in WEAK_TLS_CIPHERS:
                    findings.append({
                        "port": port,
                        "tls_version": version,
                        "message": f"Port {port}: Weak TLS version detected ({version})",
                        "msg": f"Weak TLS version detected ({version})"
                    })
                else:
                    findings.append({
                        "port": port,
                        "tls_version": version,
                        "message": f"Port {port}: TLS version {version}",
                        "msg": f"TLS version {version}"
                    })

                return findings

    except Exception as exc:
        findings.append({
            "port": port,
            "tls_version": "unreachable",
            "message": f"Port {port}: TLS check failed ({exc})",
            "msg": f"TLS check failed ({exc})"
        })

    return findings
