from scapy.all import sniff, DHCP

def process(packet):

    if packet.haslayer(DHCP):

        print("DHCP packet detected")

def start_dhcp_listener():

    sniff(filter="udp and (port 67 or 68)", prn=process)