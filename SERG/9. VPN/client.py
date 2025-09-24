import os, fcntl, struct, socket, select, subprocess, signal, sys, argparse, time, base64, binascii
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- TUN constants ---
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def run(cmd): subprocess.check_call(cmd, shell=True)

def setup_tun(name: str, addr_cidr: str, mtu: int = 1380):
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)
    real_name = ifs[:16].strip(b'\x00').decode()
    run(f"ip addr add {addr_cidr} dev {real_name}")
    run(f"ip link set {real_name} up")
    run(f"ip link set {real_name} mtu {mtu}")
    return tun, real_name

def load_psk(psk: str):
    if psk.startswith("base64:"):
        key = base64.b64decode(psk.split(":",1)[1].encode())
    elif psk.startswith("hex:"):
        key = binascii.unhexlify(psk.split(":",1)[1].encode())
    else:
        key = psk.encode()
    if len(key) != 32:
        print(f"[ERR] PSK must be exactly 32 bytes, got {len(key)}")
        sys.exit(1)
        
    return key

def aead_encrypt(aead: ChaCha20Poly1305, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, plaintext, None)
    return nonce + ct

def aead_decrypt(aead: ChaCha20Poly1305, packet: bytes) -> bytes:
    if len(packet) < 12 + 16:
        return b""
    nonce, ct = packet[:12], packet[12:]
    try:
        return aead.decrypt(nonce, ct, None)
    except Exception:
        return b""

def main():
    ap = argparse.ArgumentParser(description="Tiny TUN over UDP - Client (ChaCha20-Poly1305)")
    ap.add_argument("--tun-addr", default="10.8.0.2/24", help="Адрес/маска для TUN (client)")
    ap.add_argument("--tun-name", default="tun0", help="Имя TUN интерфейса")
    ap.add_argument("--server",   required=True, help="server_ip:port (UDP)")
    ap.add_argument("--mtu", type=int, default=1380, help="MTU для TUN")
    args = ap.parse_args()
    args.psk = "base64:yP6+esuGK8YGqkEV//OsUovEJWzrQnXj+Z2Snyy37nk="

    key = load_psk(args.psk)
    aead = ChaCha20Poly1305(key)

    tun_fd, tun_name = setup_tun(args.tun_name, args.tun_addr, args.mtu)
    print(f"[OK] TUN {tun_name} up at {args.tun_addr}, MTU {args.mtu}")

    srv_host, srv_port = args.server.split(":")
    srv_port = int(srv_port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((srv_host, srv_port))
    sock.setblocking(False)

    def cleanup(*_):
        try: run(f"ip link set {tun_name} down")
        except Exception: pass
        os.close(tun_fd); sock.close()
        print("\n[INFO] Client stopped."); sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Первичное "HELLO" для проброса NAT — теперь тоже шифруем
    sock.send(aead_encrypt(aead, b"HELLO"))
    last_keep = time.time()

    while True:
        r, _, _ = select.select([sock, tun_fd], [], [], 1.0)

        # UDP -> TUN (дешифруем и кладем в TUN)
        if sock in r:
            data = sock.recv(65535)
            payload = aead_decrypt(aead, data)
            if payload not in (b"", b"\x00"):
                os.write(tun_fd, payload)

        # TUN -> UDP (шифруем и отправляем)
        if tun_fd in r:
            packet = os.read(tun_fd, 65535)
            enc = aead_encrypt(aead, packet)
            sock.send(enc)

        # keepalive
        if time.time() - last_keep > 15:
            sock.send(aead_encrypt(aead, b"\x00"))
            last_keep = time.time()

if __name__ == "__main__":
    main()
