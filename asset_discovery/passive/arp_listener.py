from scapy.all import sniff, ARP

def process(packet):

    if packet.haslayer(ARP):

        print({
            "ip": packet.psrc,
            "mac": packet.hwsrc
        })

def start_arp_listener():

    sniff(filter="arp", prn=process, store=False)