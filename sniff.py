from scapy.all import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.packet import Raw
from scapy.utils import PcapWriter


def sniff_goose(interface):
    print("GOOSE messages use IEEE 802.1Q for VLAN tagging and prioritization. Many network cards filter out the "
          "content of this layer. If this is also the case for you, there are often ways to change this. Since it "
          "varies from card to card you should google it. Otherwise you can answer 'Tagged VLANs' with n.")
    time_to_capture = int(input("Time to capture (in seconds) : "))
    with_iee = input("Does your interface support tagged VLANs? (y/n): ")
    capture_name = input("Name of the pcap file (without extension) : ")
    print(
        '\nSniffing GOOSE traffic from '
        '\n[*] Interface: {} '
        '\n[*] For:{} seconds '
        '\n[*] Tagged VLANs: {} '
        '\n'.format(interface, time_to_capture, with_iee))

    if with_iee == "y":
        # Sniffing the traffic from Publisher
        print("All network packets with Ethernet, IEEE 802.1Q and RAW Layer are captured!")
        traffic = sniff(iface=interface, timeout=time_to_capture)
        output = PcapWriter(capture_name + ".pcap", append=True, sync=True)

        for frame in traffic:  # Checks all frames in traffic
            if frame.haslayer(Ether) == 1 and frame.haslayer(Dot1Q) == 1 and frame.haslayer(
                    Raw) == 1:  # Checks if the frame has the Ethernet, IEEE802.1Q and Raw layer
                output.write(frame)  # Saves the frame
        print("File saved as: " + capture_name)

    elif with_iee == "n":
        # Sniffing the traffic from Publisher
        print("All network packets with Ethernet and RAW Layer are captured!")
        traffic = sniff(iface=interface, timeout=time_to_capture)
        output = PcapWriter(capture_name + ".pcap", append=True, sync=True)

        for frame in traffic:  # Checks all frames in traffic
            if frame.haslayer(Ether) == 1 and frame.haslayer(
                    Raw) == 1:  # Checks if the frame has the Ethernet, and Raw layer
                output.write(frame)  # Saves the frame
        print("File saved as: " + capture_name)

    else:
        print("Your Input was: ", with_iee, "It should be 'y' or 'n'!")
