import socket
from scapy.all import ARP, Ether, srp
from netaddr import EUI
from config.settings import settings

def get_hostname(ip):
    try:
        socket.setdefaulttimeout(1.5)
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_mac(ip):
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        result = srp(packet, timeout=min(settings.SCAN_TIMEOUT, 2), verbose=0)[0]

        for sent, received in result:
            return received.hwsrc

    except:
        pass

    return None

def get_vendor(mac):
    try:
        if mac:
            return EUI(mac).oui.registration().org
    except:
        pass
    return "Unknown"
