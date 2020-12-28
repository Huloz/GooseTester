import time

from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp
from scapy.utils import rdpcap


def replay_goose(interface):
    pcap_name = input("\n[*] Enter the name of the PCAP file to be used (without extension): ")

    packets = rdpcap(pcap_name + '.pcap')
    for packet in packets:
        if packet.haslayer(Ether) == 1:                # and packet.haslayer(Dot1Q) == 1 and packet.haslayer(Raw) == 1
            print(packet)
            sendp(packet, iface=interface)
            time.sleep(0.01)
