#!/usr/bin/env python
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    # print(arp_request.summary())
    # scapy.ls(scapy.ARP())
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    # scapy.ls(scapy.Ether())
    arp_request_broadcast = broadcast / arp_request
    # arp_request_broadcast.show()
    # answered, unanswered = scapy.srp(arp_request_broadcast, timeout=1)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(answered.summary())

    clint_list = []

    for element in answered_list:
        clint_list.append({
            "ip": element[1].psrc,
            "mac": element[1].hwsrc
        })
        # print(element[1].show())
        # print(element[1].psrc + "\t\t\t" + element[1].hwsrc)
        # print("-------------------------------------------------------------------")
    return clint_list


def print_result(result_list):
    print("IP\t\t\t\tMAC_ADDRESS\n-------------------------------------------------------------------")
    for clint in result_list:
        print(clint["ip"]+"\t\t\t"+clint["mac"])

ip_address = input("enter a rang\n")
scan_result = scan(ip_address)
print_result(scan_result)

