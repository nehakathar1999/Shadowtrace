from collections import Counter

try:
    from scapy.all import IP, TCP, UDP, ICMP, sniff
except Exception:
    IP = TCP = UDP = ICMP = None
    sniff = None


SUSPICIOUS_PORTS = {4444, 5555, 6667, 1337, 31337}
MALWARE_KEYWORDS = ("meterpreter", "powershell", "cmd.exe", "mimikatz", "cobalt", "beacon")


def sniff_network_traffic(targets: list[str] | None = None, duration: int = 8) -> dict:
    summary = {
        "enabled": sniff is not None,
        "duration_seconds": duration,
        "live_hosts": [],
        "protocol_usage": [],
        "suspicious_traffic": [],
        "malware_patterns": [],
    }
    if sniff is None:
        summary["note"] = "Scapy sniffing unavailable in this environment."
        return summary

    packets = []
    target_set = {str(item).strip() for item in (targets or []) if str(item).strip()}

    def collect(packet):
        packets.append(packet)

    try:
        sniff(timeout=max(1, int(duration)), prn=collect, store=False)
    except Exception as exc:
        summary["enabled"] = False
        summary["note"] = f"Traffic sniff failed: {exc}"
        return summary

    live_hosts = set()
    protocol_counter = Counter()
    suspicious = []
    malware_patterns = []

    for packet in packets:
        if IP and packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            if not target_set or src in target_set or dst in target_set:
                live_hosts.add(src)
                live_hosts.add(dst)

            proto_name = "IP"
            if TCP and packet.haslayer(TCP):
                proto_name = "TCP"
                dport = int(packet[TCP].dport)
                if dport in SUSPICIOUS_PORTS:
                    suspicious.append({
                        "type": "suspicious_port",
                        "src": src,
                        "dst": dst,
                        "port": dport,
                        "detail": f"Traffic observed on suspicious port {dport}.",
                    })
                payload_text = bytes(packet[TCP].payload).decode("utf-8", errors="ignore").lower()
                for keyword in MALWARE_KEYWORDS:
                    if keyword in payload_text:
                        malware_patterns.append({
                            "type": "keyword_match",
                            "src": src,
                            "dst": dst,
                            "keyword": keyword,
                        })
            elif UDP and packet.haslayer(UDP):
                proto_name = "UDP"
            elif ICMP and packet.haslayer(ICMP):
                proto_name = "ICMP"

            protocol_counter[proto_name] += 1

    summary["live_hosts"] = sorted(host for host in live_hosts if host and host != "0.0.0.0")
    summary["protocol_usage"] = [
        {"protocol": proto, "count": count}
        for proto, count in protocol_counter.most_common()
    ]
    summary["suspicious_traffic"] = suspicious[:20]
    summary["malware_patterns"] = malware_patterns[:20]
    return summary
