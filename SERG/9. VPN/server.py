import os, fcntl, struct, socket, select, subprocess, signal, sys, argparse, time, base64, binascii
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- TUN constants ---
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

def run(cmd): subprocess.check_call(cmd, shell=True)

def setup_tun(name: str, addr_cidr: str, mtu: int = 1380):
    # Создание TUN
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack('16sH', name.encode(), IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)
    real_name = ifs[:16].strip(b'\x00').decode()
    # Настройка адреса и MTU (чуть меньше из-за оверхеда AEAD+UDP)
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
    nonce = os.urandom(12)               # 96-bit nonce
    ct = aead.encrypt(nonce, plaintext, None)
    return nonce + ct                    # отправляем nonce перед шифртекстом

def aead_decrypt(aead: ChaCha20Poly1305, packet: bytes) -> bytes:
    if len(packet) < 12 + 16:            # nonce + минимум тэг
        return b""
    nonce, ct = packet[:12], packet[12:]
    try:
        return aead.decrypt(nonce, ct, None)
    except Exception:
        return b""

def main():
    ap = argparse.ArgumentParser(description="Tiny TUN over UDP - Server (ChaCha20-Poly1305)")
    ap.add_argument("--tun-addr", default="10.8.0.1/24", help="Адрес/маска для TUN (server)")
    ap.add_argument("--tun-name", default="tun0", help="Имя TUN интерфейса")
    ap.add_argument("--listen",   default="0.0.0.0:51820", help="Слушать addr:port (UDP)")
    ap.add_argument("--mtu", type=int, default=1380, help="MTU для TUN (учти оверхед AEAD+UDP)")
    args = ap.parse_args()
    args.psk = "base64:yP6+esuGK8YGqkEV//OsUovEJWzrQnXj+Z2Snyy37nk="

    key = load_psk(args.psk)
    aead = ChaCha20Poly1305(key)

    tun_fd, tun_name = setup_tun(args.tun_name, args.tun_addr, args.mtu)
    print(f"[OK] TUN {tun_name} up at {args.tun_addr}, MTU {args.mtu}")

    host, port = args.listen.split(":")
    port = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.setblocking(False)
    print(f"[OK] UDP listen on {host}:{port}")

    peer = None
    last_keep = 0

    def cleanup(*_):
        try: run(f"ip link set {tun_name} down")
        except Exception: pass
        os.close(tun_fd); sock.close()
        print("\n[INFO] Server stopped."); sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    while True:
        r, _, _ = select.select([sock, tun_fd], [], [], 1.0)

        # UDP -> TUN (принимаем зашифрованный пакет)
        if sock in r:
            data, src = sock.recvfrom(65535)
            if peer is None:
                peer = src
                print(f"[INFO] Learned client {peer}")
            if src == peer:
                payload = aead_decrypt(aead, data)
                if payload not in (b"", b"\x00"):
                    os.write(tun_fd, payload)

        # TUN -> UDP (шифруем и отправляем клиенту)
        if tun_fd in r and peer:
            packet = os.read(tun_fd, 65535)
            enc = aead_encrypt(aead, packet)
            sock.sendto(enc, peer)

        # keepalive
        now = time.time()
        if peer and now - last_keep > 15:
            sock.sendto(aead_encrypt(aead, b"\x00"), peer)
            last_keep = now

if __name__ == "__main__":
    main()
