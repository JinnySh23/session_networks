import os
import fcntl
import struct
import socket
import subprocess
import select

# --- Создаём TUN интерфейс ---
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack("16sH", b"tun0", IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes[:16].strip(b"\x00").decode("utf-8")
print("Создан интерфейс:", ifname)

# Назначаем IP и поднимаем
subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", ifname], stderr=subprocess.DEVNULL)
subprocess.run(["ip", "link", "set", "dev", ifname, "up"])

# --- UDP сокет ---
SERVER_IP = "0.0.0.0"
SERVER_PORT = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((SERVER_IP, SERVER_PORT))
print(f"VPN сервер слушает на {SERVER_IP}:{SERVER_PORT}")

clients = set()

# --- Основной цикл ---
while True:
    r, _, _ = select.select([tun, sock], [], [])
    for fd in r:
        if fd == tun:
            packet = os.read(tun, 2048)
            for addr in clients:
                sock.sendto(packet, addr)
        elif fd == sock:
            data, addr = sock.recvfrom(2048)
            clients.add(addr)
            os.write(tun, data)
