#!/usr/bin/env python
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clint_list = []
    for element in answered_list:
        clint_list.append({
            "ip": element[1].pdst,
            "mac": element[1].hwsrc
        })
    return clint_list

def print_result(search_result):
    print("IP\t\t\tMac_address\n--------------------------------------------------------")
    for clint in search_result:
        print(clint["ip"]+"\t\t\t"+clint["mac"])


search_result = scan("10.0.2.1/24")
print_result(search_result)

