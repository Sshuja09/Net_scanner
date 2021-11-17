#!/usr/bin/env python3
import scapy.all as scapy
import optparse

# This will scan and return all the MAC and IP address combination on the network.
def net_scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_req
    answer_list = scapy.srp(arp_broadcast, timeout=1, verbose=False)[0]
    scan_list = []
    for element in answer_list:
        scan_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        scan_list.append(scan_dictionary)
    return scan_list

# This will parser through the command line get the given IP or IP range
def get_ip():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Enter an IP address or an IP range")
    ip = parser.parse_args()[0]
    if not ip.target:
        parser.error("Please enter a Ip addres or a range")
    return ip

# This will print each MAC and IP address pair
def print_result(ip_list):
    print("    IP \t\t\t\tMAC")
    print("----" * 13)
    for place, element in enumerate(ip_list):
        print(place, element["ip"], "\t\t", element["mac"])


ip_range = get_ip()
scan_result = net_scan(ip_range.target) # .target is the field that contains the entered ip in (The add_option method "dest")
print_result(scan_result)
