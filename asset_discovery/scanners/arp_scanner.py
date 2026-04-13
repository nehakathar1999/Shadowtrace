from scapy.all import ARP, Ether, srp

def arp_scan(network):

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)

    result = srp(packet, timeout=2, verbose=0)[0]

    hosts = []

    for sent, received in result:
        hosts.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return hosts