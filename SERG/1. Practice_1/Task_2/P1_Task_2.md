# Задание 2: Работа с tshark

## Установка tshark

Для скачивания и установки tshark, сначала обновим репозитории: **sudo apt update**

Затем произведём установку tshark: **sudo apt install tshark -y**, сразу с параметром -y (Да, установить).

После установки для проверки наличия программы вводим в терминал команду: **tshark -v**

```bash
serg@serg-pc:~$ tshark -v
TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).

Copyright 1998-2024 Gerald Combs <gerald@wireshark.org> and contributors.
Licensed under the terms of the GNU General Public License (version 2 or later).
This is free software; see the file named COPYING in the distribution. There is
NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) using GCC 13.2.0, with GLib 2.80.0, with libpcap, with POSIX
capabilities (Linux), with libnl 3, with zlib 1.3, with PCRE2, with Lua 5.2.4,
with GnuTLS 3.8.3 and PKCS #11 support, with Gcrypt 1.10.3, with Kerberos (MIT),
with MaxMind, with nghttp2 1.59.0, with nghttp3 0.8.0, with brotli, with LZ4,
with Zstandard, with Snappy, with libxml2 2.9.14, with libsmi 0.4.8, with binary
plugins.

Running on Linux 6.14.0-29-generic, with AMD Ryzen 3 2200G with Radeon Vega
Graphics (with SSE4.2), with 7941 MB of physical memory, with GLib 2.80.0, with
libpcap 1.10.4 (with TPACKET_V3), with zlib 1.3, with PCRE2 10.42 2022-12-11,
with c-ares 1.27.0, with GnuTLS 3.8.3, with Gcrypt 1.10.3, with nghttp2 1.59.0,
with nghttp3 0.8.0, with brotli 1.1.0, with LZ4 1.9.4, with Zstandard 1.5.5,
with libsmi 0.4.8, with LC_TYPE=en_US.UTF-8, binary plugins supported.

```

Данный вывод говорит о том, что программа tshark успешно установилась и имеет версию 4.2.2.

## Работа в программе tshark

В начале нам необходимо получить список сетевых интерфейсов для выявления активного, при помощи команды **sudo tshark -D**:

```bash
serg@serg-pc:~$ sudo tshark -D
Running as user "root" and group "root". This could be dangerous.
1. enp0s3
2. any
3. lo (Loopback)
4. bluetooth-monitor
5. nflog
6. nfqueue
7. dbus-system
8. dbus-session
9. ciscodump (Cisco remote capture)
10. dpauxmon (DisplayPort AUX channel monitor capture)
11. randpkt (Random packet generator)
12. sdjournal (systemd Journal Export)
13. sshdump (SSH remote capture)
14. udpdump (UDP Listener remote capture)
15. wifidump (Wi-Fi remote capture)
```

Предполагаю, что мой активный интерфейс, это адаптер - enp0s3. Но более точную информацию я могу получить, введя команду: **ip addr**

```bash
serg@serg-pc:~$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:42:bd:d7 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute enp0s3
       valid_lft 58848sec preferred_lft 58848sec
    inet6 fd17:625c:f037:2:ffa0:99c7:a107:c51f/64 scope global temporary dynamic 
       valid_lft 86209sec preferred_lft 14209sec
    inet6 fd17:625c:f037:2:90e4:4c53:fabe:e1eb/64 scope global dynamic mngtmpaddr noprefixroute 
       valid_lft 86209sec preferred_lft 14209sec
    inet6 fe80::43cc:8e13:c564:aebf/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
```

Из вывода понятно, что мой основной адаптер имеет название enp0s3. Следовательно возвращаясь к выводу от tshark получаем, что номер нашего активного интерфейса - 1. Зная это, можно сформировать команду для захвата ARP пакета: **sudo timeout 180 tshark -i 1 -f "arp" > arp_log.txt**, где:

- **timeout 180** - это время захвата (180 секунд = 3 минуты);

- -i 1 - номер моего активного интерфейса;

- -f "arp" - фильтр захвата (только ARP пакеты);

- `>arp_log.txt` - сохраняет вывод в файл "arp_log.txt"

Запускаем код и следим за работой программы:

```bash
serg@serg-pc:~$ sudo timeout 180 tshark -i 1 -f "arp" > arp_log.txt
[sudo] password for serg:       
Running as user "root" and group "root". This could be dangerous.
Capturing on 'enp0s3'
10
```

Посмотрим вывод в txt файле:

```bash
3 1.020415848 PCSSystemtec_42:bd:d7 → Broadcast    ARP 58 Who has 10.0.2.2? Tell 10.0.2.15
4 1.020574872 52:55:0a:00:02:02 → PCSSystemtec_42:bd:d7 ARP 64 10.0.2.2 is at 52:55:0a:00:02:02
```

Разберём результат **первой строки**:

- 3 - номер пакета в захвате;

- 1.020415848 - относительное время (в секундах) с момента старта захвата: этот пакет пришёл через ~1.0204 с после начала записи;

- `PCSSystemtec_42:bd:d7` - исходный MAC-адрес отправителя в укороченном/дружественном виде. tshark показывает часть OUI (производитель маршрутизатора) + остаток MAC. В «сырых» байтах это что-то вроде `xx:xx:xx:42:bd:d7`;

- → Broadcast - адрес назначения: широковещательный `ff:ff:ff:ff:ff:ff`. Строка стрелкой показывает направление «src → dst»;

- ARP - протокол на уровне 3/2 (здесь ARP);

- 58 - длина фрейма (в байтах);

- Who has 10.0.2.2? Tell 10.0.2.15 - вполне читаемая расшифровка содержимого ARP-пакета: это **ARP-request**. Значение читается примерно как: «Кто владеет IP 10.0.2.2? Сообщите мне (10.0.2.15);

Разберём результат **второй строки**:

- 4 - номер пакета;

- 1.020574872 - время: 1.020574872 с от старта (т.е. ответ пришёл очень быстро после запроса - ~0.00016 с позже);

- `52:55:0a:00:02:02` - исходный MAC отправителя этого пакета (уже другой хост в сети — тот, кто владеет IP 10.0.2.2);

- → `PCSSystemtec_42:bd:d7` - адрес назначения: это уже уникаст (ответ направлен конкретно на MAC запроса), поэтому видно конкретный MAC получателя;

- ARP 64 - протокол ARP, длина 64 байта;

- `10.0.2.2 is at 52:55:0a:00:02:02` - ARP-reply (ответ): «IP 10.0.2.2 находится на MAC `52:55:0a:00:02:02`»;

Что по итогу происходило:

1. Хост с MAC `PCSSystemtec_42:bd:d7` и IP 10.0.2.15 не знает MAC для IP 10.0.2.2. Он отправляет ARP-запрос (Who has 10.0.2.2?) на широковещательный адрес, чтобы любой узел в локальной сети мог ответить. Поэтому dst равен Broadcast.

2. Узел, чей IP = 10.0.2.2, видит запрос и посылает ARP-ответ (ARP reply) **на конкретный MAC отправителя** (уникаст) с сообщением `10.0.2.2 is at 52:55:0a:00:02:02`. Операционная система отправителя при получении такого ответа заносит пару (10.0.2.2 → `52:55:0a:00:02:02`) в ARP-кеш.

3. После этого отправитель может направлять Ethernet-кадры на MAC `52:55:0a:00:02:02` для IP 10.0.2.2.

Итого, при помощи программы tshark я перехватил служебный broadcast-запрос от устройства с IP: 10.0.2.15, который пытается найти в локальной сети устройство с адресом 10.0.2.2, чтобы получить его MAC адрес, для отправки на него данных.
