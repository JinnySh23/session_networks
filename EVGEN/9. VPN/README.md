# Собственный VPN сервер

Я арендую сервер на сервисе аренды серверов - [timeweb](https://timeweb.com/)

## Характеристики сервера:

- **ОС**: Ubuntu 24.04;

- **ЦП**: 1 x 3.3 ГГц;

- **ОЗУ**: 1 Гб;

- **Канал**: 1 Гбит/с;

- **NVMe**: 15 Гб;

- **IP-адрес**: 185.119.59.96;

Скрипт предварительной настройки сервера после его создания:

```bash
#!/bin/sh

# === 1. Создание пользователя webmaster ===
WEBMASTER_PASS="*************"
USERNAME="webmaster"

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
ufw allow 5555/udp
ufw enable

# Вывести сообщение о завершении
echo "Первичная настройка завершена! Пользователь $USERNAME создан, оболочка Bash установлена, SSH настроен на порт 250, UFW включён."
```

## Процесс установки:

1. Включение форвардинга пакетов:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Чтобы включение сохранялось после перезагрузки открываем конфиг sysctl:

```bash
sudo nano /etc/sysctl.conf
```

Добавляем строку:

```bash
net.ipv4.ip_forward = 1
```

И применяем:

```bash
sudo sysctl -p
```

2. Далее на сервере создаём файл "[vpn_server.py](./vpn_server.py)":

```python
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
```

3. Далее на клиенте создаём файл "[vpn_client.py](./vpn_client.py)":

```python
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
subprocess.run(["ip", "addr", "add", "10.0.0.2/24", "dev", ifname], stderr=subprocess.DEVNULL)
subprocess.run(["ip", "link", "set", "dev", ifname, "up"])

# --- UDP сокет ---
SERVER_IP = "185.119.59.96"
SERVER_PORT = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"VPN клиент подключается к {SERVER_IP}:{SERVER_PORT}")

# --- Основной цикл ---
while True:
    r, _, _ = select.select([tun, sock], [], [])
    for fd in r:
        if fd == tun:
            packet = os.read(tun, 2048)
            sock.sendto(packet, (SERVER_IP, SERVER_PORT))
        elif fd == sock:
            data, _ = sock.recvfrom(2048)
            os.write(tun, data)
```

4. **Запуск туннеля**. На **сервере** выполняем:

```bash
sudo python vpn_server.py
```

На **клиенте** выполняем:

```bash
sudo python vpn_client.py
```

## Проверка работоспособности

Теперь можно выполнить пинг. На **клиенте** выполняем:

```bash
evgeny@home-pc:~$ ping 10.0.0.1
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=19.0 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=13.9 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=8.66 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=2.81 ms
64 bytes from 10.0.0.1: icmp_seq=5 ttl=64 time=6.05 ms
64 bytes from 10.0.0.1: icmp_seq=6 ttl=64 time=2.11 ms
64 bytes from 10.0.0.1: icmp_seq=7 ttl=64 time=2.00 ms
64 bytes from 10.0.0.1: icmp_seq=8 ttl=64 time=2.08 ms
^C
--- 10.0.0.1 ping statistics ---
8 packets transmitted, 8 received, 0% packet loss, time 7065ms
rtt min/avg/max/mdev = 1.998/7.080/19.035/5.989 ms
```

На **сервере** выполняем:

```bash
webmaster@5707201-rresearch:~$ ping 10.0.0.2
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=7.25 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=2.09 ms
64 bytes from 10.0.0.2: icmp_seq=3 ttl=64 time=1.73 ms
64 bytes from 10.0.0.2: icmp_seq=4 ttl=64 time=1.89 ms
64 bytes from 10.0.0.2: icmp_seq=5 ttl=64 time=2.05 ms
64 bytes from 10.0.0.2: icmp_seq=6 ttl=64 time=2.16 ms
^C
--- 10.0.0.2 ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5008ms
rtt min/avg/max/mdev = 1.734/2.864/7.251/1.966 ms
```

## Вывод

В ходе работы был реализован собственный VPN-механизм без использования готовых решений. Основная идея заключалась в том, чтобы перехватывать пакеты с виртуального интерфейса **TUN**, передавать их через сокет и восстанавливать на другой стороне.
