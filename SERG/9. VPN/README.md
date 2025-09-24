# Свой простой VPN сервер

Возьмём **tun/tap-интерфейсы** и соединим их через **UDP-сокет + шифрование**

```scss
Client <—UDP—> Server (VPS)
    tun0 ↔ socket ↔ tun0
```

Внутри `tun0` будут ходить пакеты (например, ICMP/ping).

Сокет пересылает их между клиентом и сервером.

Я арендовал сервер на сервисе аренды серверов - [timeweb](https://timeweb.com/)

## Сервер:

- **OS**: Ubuntu 24.04;

- **CPU**: 1 x 3.3 ГГц;

- **RAM**: 1 Гб;

- **NVMe Диск**: 15 Гб;

- **Канал**: 1 Гбит/с;

- **IP-адрес**: 185.119.59.96;

## Установка

1. Предварительно сервер на таймвебе можно настроить, добавив собственный скрипт в **Cloud-init**:

```bash
#!/bin/sh

# === 1. Создание пользователя master ===
WEBMASTER_PASS="*************"
USERNAME="master"

# Создать пользователя с оболочкой bash
useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$WEBMASTER_PASS" | chpasswd

# Добавить пользователя в sudo
usermod -aG sudo "$USERNAME"

# === 2. Настройка SSH ===
SSHD_CONFIG="/etc/ssh/sshd_config"

# Изменение порта SSH, запрет root-входа и аутентификации по паролю
sed -i 's/^#Port 22/Port ***/' "$SSHD_CONFIG"
sed -i -E 's/^#?PermitRootLogin\s+.+/PermitRootLogin no/' "$SSHD_CONFIG"
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' "$SSHD_CONFIG"

# Перезапуск SSH с использованием сокета
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket

# === 3. Настройка UFW ===
ufw default deny incoming
ufw default allow outgoing
ufw allow ***/tcp
ufw allow 51820/udp
ufw enable

# Вывести сообщение о завершении
echo "Первичная настройка завершена! Пользователь $USERNAME создан, оболочка Bash установлена, SSH настроен на порт 250, UFW включён."
```

2. Включаем поддержку tun на сервере и клиенте в Linux:

```bash
sudo modprobe tun
ls /dev/net/tun
```

Если в выводе видим:

```bash
/dev/net/tun
```

Значит всё хорошо.

3. Включение форвардинг на **сервере**:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Для сохранения после перезагрузки **сервера**, открываем конфиг sysctl:

```bash
sudo nano /etc/sysctl.conf
```

Добавляем строку в файл:

```bash
net.ipv4.ip_forward = 1
```

И применяем добавление:

```bash
sudo sysctl -p
```

4. Установка зависимостей

На **сервере** и **клиенте** установим библиотеку **cryptography**:

```bash
sudo apt install python3-cryptography
```

5. Для шифрования генерируем на **сервере** **32-байтовый ключ** (256 бит), закодированный в Base64:

```bash
openssl rand -base64 32
```

Он нам понадобится в наших Python скриптах ниже.

6. Далее на сервере создаём файл "[server.py](./server.py)":

```python
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

def load_psk(psk: str, psk_file: str):
    if psk_file:
        with open(psk_file, "rb") as f:
            key = f.read()
    else:
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

    key = load_psk(args.psk, args.psk_file)
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

```

7. Далее на клиенте создаём файл "[client.py](./client.py)":

```python
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

def load_psk(psk: str, psk_file: str):
    if psk_file:
        with open(psk_file, "rb") as f:
            key = f.read()
    else:
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

    key = load_psk(args.psk, args.psk_file)
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

```

8. **Запуск VPN**. На **сервере** выполняем:

```bash
sudo python3 server.py --tun-addr 10.8.0.1/24 --listen 0.0.0.0:51820
```

На **клиенте** выполняем:

```bash
sudo python3 client.py --tun-addr 10.8.0.2/24 --server 185.119.59.96:51820
```

## Проверка работы

Теперь для проверки выполним пинг. На **клиенте** выполняем:

```bash
serg@serg-pc:~$ ping -c 4 10.8.0.1
PING 10.8.0.1 (10.8.0.1) 56(84) bytes of data.
64 bytes from 10.8.0.1: icmp_seq=1 ttl=64 time=3.17 ms
64 bytes from 10.8.0.1: icmp_seq=2 ttl=64 time=2.60 ms
64 bytes from 10.8.0.1: icmp_seq=3 ttl=64 time=2.33 ms
64 bytes from 10.8.0.1: icmp_seq=4 ttl=64 time=2.25 ms

--- 10.8.0.1 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 2.250/2.586/3.172/0.361 ms
```

На **сервере** выполняем:

```bash
master@609457-sdl:~$ ping -c 4 10.8.0.2
PING 10.8.0.2 (10.8.0.2) 56(84) bytes of data.
64 bytes from 10.8.0.2: icmp_seq=1 ttl=64 time=2.42 ms
64 bytes from 10.8.0.2: icmp_seq=2 ttl=64 time=3.54 ms
64 bytes from 10.8.0.2: icmp_seq=3 ttl=64 time=2.41 ms
64 bytes from 10.8.0.2: icmp_seq=4 ttl=64 time=2.52 ms

--- 10.8.0.2 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3005ms
rtt min/avg/max/mdev = 2.405/2.721/3.539/0.473 ms
```

## Вывод

В ходе работы был реализован собственный VPN-туннель на основе TUN-интерфейсов и UDP-сокетов.
Для защиты передаваемых данных был добавлен слой шифрования с использованием алгоритма **ChaCha20-Poly1305**, обеспечивающего конфиденциальность и целостность трафика.

Сервер и клиент успешно подняли виртуальные интерфейсы `tun0` с адресами `10.8.0.1/24` и `10.8.0.2/24` соответственно. После запуска скриптов пакеты ICMP (ping) между узлами проходили через зашифрованный канал, что подтверждает корректную работу решения.

Таким образом, цель проекта достигнута: создан рабочий VPN-канал без применения готовых решений (OpenVPN, WireGuard и др.), реализованы собственные механизмы передачи и шифрования трафика, проверена работоспособность с помощью утилиты `ping`.
