from scapy.all import sniff

def process_packet(packet):

    if packet.haslayer("IP"):
        print(packet.summary())

def start_sniffer():

    sniff(prn=process_packet, store=False)