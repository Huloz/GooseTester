import sys

from scapy.arch import get_windows_if_list, get_if_list

import replay
import sniff


def return_interfaces():
    win_list = get_windows_if_list()
    intf_list = get_if_list()

    # Pull guids and names from the windows list
    guid_to_name_dict = {e["guid"]: e["name"] for e in win_list}

    # Extract the guids from the interface listEth
    guids_from_intf_list = [(e.split("_"))[1] for e in intf_list]

    # Using the interface list of guids, pull the names from the
    # Windows map of guids to names
    names_allowed_list = [guid_to_name_dict.get(e) for e in guids_from_intf_list]
    print(names_allowed_list)


try:
    print("\n")
    print("      ======================================================================")
    print("      |                   G  O  O   S   E   -  T E S T E R                 |")
    print("      |++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++|")
    print("      |                                                                    |")
    print("      |                This program uses the framework scapy               |")
    print("      |               Use exclusively for tests in own network             |")
    print("      |                 The GOOSE-Message is part of IEC61850              |")
    print("      |                              standard                              |")
    print("      |                                                                    |")
    print("      |++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++|")
    print("      |                          Author: Erik Krupke                       |")
    print("      ======================================================================")
    print("\n")
    print("List of interfaces: ")
    return_interfaces()
    print("\n")
    interface = input("Enter the name of the interface to be used: ")
except KeyboardInterrupt:
    print("\n Process Interrupted by user!")
    sys.exit(1)
while True:
    choice = input(
        "\n[1] SNIFF GOOSE TRAFFIC AND SAVE IT AS A PCAP FILE"
        "\n[2] REPLAY GOOSE TRAFFIC "
        "\n[0] EXIT THE GOOSE GENERATOR "
        "\n"
        "\nPLEASE SELECT YOUR OPTION: ")
    if choice == "1":
        sniff.sniff_goose(interface)
        break
    elif choice == "2":
        replay.replay_goose(interface)
        break
    elif choice == "0":
        sys.exit(1)
