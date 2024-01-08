#!/usr/bin/env python3
import scapy.all as scapy
import optparse

# This function performs network scanning and returns a list of dictionaries with IP and MAC addresses.
def net_scan(ip):
    # Create an ARP request packet
    arp_req = scapy.ARP(pdst=ip)
    # Create an Ethernet frame with a broadcast MAC address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request to form a broadcast packet
    arp_broadcast = broadcast / arp_req
    # Send the broadcast packet and receive the responses
    answer_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    scan_list = []
    for element in answer_list:
        # Extract IP and MAC addresses from the responses and add to the list
        scan_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        scan_list.append(scan_dictionary)
    return scan_list

# This function parses the command line arguments to get the target IP or IP range
def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter an IP address or an IP range")
    ip = parser.parse_args()[0]
    if not ip.target:
        parser.error("Please enter an IP address or a range")
    return ip

# This function prints the results of the network scan
def print_result(ip_list):
    print("    IP \t\t\t\tMAC")
    print("----" * 13)
    for place, element in enumerate(ip_list):
        print(place, element["ip"], "\t\t", element["mac"])

# Get the target IP or IP range from the command line
ip_range = get_ip()
# Perform network scan
scan_result = net_scan(ip_range.target)
# Print the scan results
print_result(scan_result)
