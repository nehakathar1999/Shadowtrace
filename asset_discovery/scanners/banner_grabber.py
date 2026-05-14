import socket
import ssl


HTTP_PROBES = {
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    9443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}

TLS_PORTS = {443, 8443, 9443}


def _recv_banner(sock: socket.socket, limit: int = 1024) -> str:
    try:
        data = sock.recv(limit)
        return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def grab_banner(host: str, port: int, timeout: float = 2.0) -> dict:
    result = {
        "port": port,
        "banner": "",
        "banner_source": "socket",
        "banner_status": "unavailable",
    }

    try:
        raw_sock = socket.create_connection((host, int(port)), timeout=timeout)
    except Exception:
        return result

    with raw_sock:
        sock = raw_sock
        try:
            if port in TLS_PORTS:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(raw_sock, server_hostname=host)
                result["banner_source"] = "tls"

            probe = HTTP_PROBES.get(port)
            if probe:
                sock.sendall(probe.replace(b"target", host.encode("utf-8", errors="ignore")))
                result["banner_source"] = "http"

            banner = _recv_banner(sock)
            if not banner and port in (21, 22, 25, 110, 143):
                banner = _recv_banner(sock)

            if banner:
                result["banner"] = banner[:500]
                result["banner_status"] = "captured"
        except Exception as exc:
            result["banner_status"] = f"error:{type(exc).__name__}"

    return result


def enrich_services_with_banners(host: str, services: list[dict]) -> list[dict]:
    enriched = []
    for service in services or []:
        port = service.get("port")
        if not port:
            enriched.append(service)
            continue
        banner = grab_banner(host, int(port))
        updated = dict(service)
        updated.update({
            "banner": banner.get("banner"),
            "banner_source": banner.get("banner_source"),
            "banner_status": banner.get("banner_status"),
        })
        enriched.append(updated)
    return enriched
