import scapy.all  as scapy
import argparse

def get_user_input():
    parse_object = argparse.ArgumentParser(description="Scannig Network")
    parse_object.add_argument("-i","--ipadress",dest="ip_address",help="Enter IP address")
    args = parse_object.parse_args()
    
    if not args.ip_address:
        print("Enter IP address")
    
    return args.ip_address
    


def scan_network(ip):
    # Create ARP reques
    arp_request_packet = scapy.ARP(pdst=ip) # scapy.ls(scapy.ARP()) == help

    # Broadcast
    broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff') # scapy.ls(scapy.ARP()) == help

    combined_packet =  broadcast_packet / arp_request_packet

    (answer_list,unanserd_list) = scapy.srp(combined_packet,timeout=1)
    # Response
    answer_list.summary()

user_ip_address = get_user_input()

scan_network(user_ip_address)