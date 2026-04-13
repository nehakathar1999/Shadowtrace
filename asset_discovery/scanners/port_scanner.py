import socket
from concurrent.futures import ThreadPoolExecutor
from config.settings import settings
import nmap

scanner = nmap.PortScanner()

COMMON_TCP_PORTS = [
    21,22,23,25,53,80,110,139,143,443,
    445,3389,3306,8080
]

COMMON_UDP_PORTS = [
    53,67,68,69,123,161,162,500,514,520
]




def scan_tcp_port(ip, port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port
    except Exception:
        pass
    finally:
        if sock:
            sock.close()
    return None


def scan_udp_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        # For UDP, send a dummy packet and see if we get a response
        sock.sendto(b"", (ip, port))
        sock.recvfrom(1024)
        sock.close()
        return port
    except:
        pass
    return None


def threaded_port_scan(ip):
    open_ports = []

    # Scan TCP ports
    with ThreadPoolExecutor(max_workers=settings.MAX_THREADS) as executor:
        futures = [executor.submit(scan_tcp_port, ip, port) for port in COMMON_TCP_PORTS]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)

    # Scan UDP ports
    with ThreadPoolExecutor(max_workers=settings.MAX_THREADS) as executor:
        futures = [executor.submit(scan_udp_port, ip, port) for port in COMMON_UDP_PORTS]
        for future in futures:
            port = future.result()
            if port:
                open_ports.append(port)

    return open_ports
