# Задание 2: Работа с tshark

## Установка

Для начала я скачал последнюю версию программы Wireshark и Npcap с [официального сайта](https://www.wireshark.org/download.html)

Затем я установил программу и добавил её путь в переменные окружения Windows - "C:\Program Files\Wireshark" - PATH

После я открыл командную строку и ввёл команду: **tshark -v**

```bash
C:\Windows\system32>tshark -v
TShark (Wireshark) 4.4.9 (v4.4.9-0-g57bf67214076).

Copyright 1998-2025 Gerald Combs <gerald@wireshark.org> and contributors.
Licensed under the terms of the GNU General Public License (version 2 or later).
This is free software; see the file named COPYING in the distribution. There is
NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

Compiled (64-bit) using Microsoft Visual Studio 2022 (VC++ 14.41, build 34123),
with GLib 2.80.0, with libpcap, with zlib 1.3.1, with zlib-ng 2.1.5, with PCRE2,
with Lua 5.4.6 (with UfW patches), with GnuTLS 3.8.4 and PKCS #11 support, with
Gcrypt 1.10.2-unknown, with Kerberos (MIT), with MaxMind, with nghttp2 1.62.1,
with nghttp3 0.14.0, with brotli, with LZ4, with Zstandard, with Snappy, with
libxml2 2.13.5, with libsmi 0.5.0, with binary plugins.

Running on 64-bit Windows 10 (22H2), build 19045, with AMD Ryzen 3 2200G with
Radeon Vega Graphics (with SSE4.2), with 16304 MB of physical memory, with GLib
2.80.0, without Npcap or WinPcap, with PCRE2 10.43 2024-02-16, with c-ares
1.27.0, with GnuTLS 3.8.4, with Gcrypt 1.10.2-unknown, with nghttp2 1.62.1, with
nghttp3 0.14.0, with brotli 1.0.9, with LZ4 1.9.4, with Zstandard 1.5.6, with
LC_TYPE=Russian_Russia.utf8, binary plugins supported.
```

Получив данный вывод я понял, что программа работает в консольном режиме в моей ОС.

## Работа с программой tshark

Для начала получим список сетевых интерфейсов при помощи команды **tshark -D**:

```bash
C:\Windows\system32>tshark -D
1. \Device\NPF_{05274B42-D467-41CA-9BB5-9236A73721CB} (Подключение по локальной сети* 8)
2. \Device\NPF_{145C2113-74C2-48D6-984F-0B66AA09D04B} (Подключение по локальной сети* 7)
3. \Device\NPF_{BE0FEC35-5A3E-4B47-ABE2-7A10AE332A22} (Подключение по локальной сети* 6)
4. \Device\NPF_{AC924965-04C9-45E4-8CB5-C59F63778863} (Ethernet 3)
5. \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9} (Ethernet 2)
6. \Device\NPF_Loopback (Adapter for loopback traffic capture)
7. \Device\NPF_{8206B89A-3D8F-4386-AD83-47D954B9CF67} (Ethernet)
8. etwdump (Event Tracing for Windows (ETW) reader)
```

Номер моего активного интерфейса - 5. Формируем команду для захвата ARP-пакетов на выбранном интерфейсе в течении 3-х минут: **tshark -i 5 -a duration:180 -f "arp" -Y "arp" -V > arp_capture.txt** с настройкой вывода результатов в файл.

Тут мы указали:

- **ключ -i 5** - номер моего активного интерфейса;

- **ключ -a duration:180** - указывает автоматическую остановку захвата через 180 секунд (3 минуты);

- ключ **-f "arp"** - фильтр захвата. Указывает драйверу захватывать только ARP-пакеты прямо на уровне сетевой карты. Это также снижает нагрузку на систему;

- ключ **-Y "arp"** - фильтр отображения. Показывает только ARP-пакеты из тех, что были захвачены;

- ключ **-V>arp_capture.txt** - этот ключ обеспечивает подробный вывод, раскрывая содержимое каждого поля в пакете и перенаправляя вывод из консоли в текстовый файл arp_capture.txt;

```bash
C:\Windows\system32>tshark -i 5 -a duration:180 -f "arp" -Y "arp" -V > arp_capture.txt
Capturing on 'Ethernet 2'
10
```

Запущена работа программы.

## Расшифровка результата

Берём первый фрейм для разбора:

```bash
Frame 1: 60 bytes on wire (480 bits), 60 bytes captured (480 bits) on interface \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9}, id 0
    Section number: 1
    Interface id: 0 (\Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9})
        Interface name: \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9}
        Interface description: Ethernet 2
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep 15, 2025 19:32:54.897043000 RTZ 2 (зима)
    UTC Arrival Time: Sep 15, 2025 16:32:54.897043000 UTC
    Epoch Arrival Time: 1758472374.897043000
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 60 bytes (480 bits)
    Capture Length: 60 bytes (480 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
Ethernet II, Src: TPLink_cd:bd:ea (6c:5a:b0:cd:bd:ea), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: TPLink_cd:bd:ea (6c:5a:b0:cd:bd:ea)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: ARP (0x0806)
    [Stream index: 0]
    Padding: 000000000000000000000000000000000000
Address Resolution Protocol (request)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    Sender MAC address: TPLink_cd:bd:ea (6c:5a:b0:cd:bd:ea)
    Sender IP address: 192.168.1.1
    Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)
    Target IP address: 192.168.1.105
```

В выводе у нас следующие данные:

- **Frame 1:** Это первый кадр в файле захвата;

- **60 bytes on wire:** Размер кадра в сети. Ethernet имеет минимальный размер 60 байт, поэтому даже маленькие пакеты "добиваются" до этого размера;

- **Interface: Ethernet 2:** Захват был выполнен на интерфейсе "Ethernet 2";

- **Arrival Time:** Точная дата и время, когда пакет был перехвачен (15.09.2025 в 19:32:54`);

- **Frame Length: 60 bytes:** Подтверждение размера кадра;

- **Protocols in frame: eth:ethertype:arp:** Стэк протоколов этого кадра: **Ethernet** -> **ARP**. Это самый важный пункт в заголовке, он сразу говорит, что внутри;

Далее идёт **Ethernet II (Канальный уровень)**. По сути это "конверт", в котором доставляется ARP-запрос. 

- **Destination: Broadcast** (**`ff:ff:ff:ff:ff:ff`**): **MAC-адрес `ff:ff:ff:ff:ff:ff`**- это широковещательный адрес. Пакет с таким адресом назначения **доставляется всем устройствам** в пределах локальной сети (LAN);

- **Source: TPLink_cd:bd:ea (`6c:5a:b0:cd:bd:ea`)** - **MAC-адрес отправителя:** `6c:5a:b0:cd:bd:ea`. TShark определил производителя по OUI (первым 3 байтам MAC): `6c:5a:b0` принадлежит компании **TP-Link**. Это кстати производитель моего маршрутизатора;

- **Type: ARP (0x0806)** - Это поле указывает, какой протокол находится внутри Ethernet-фрейма. Значение `0x0806` однозначно определяет, что содержимое — это **ARP-пакет**;

Рассмотрим сам **ARP-запрос Address Resolution Protocol** по сути это письмо внутри того "конверта":

- **Hardware type: Ethernet (1):** Запрос относится к Ethernet-сетям;

- **Protocol type: IPv4 (0x0800):** Запрос предназначен для разрешения **IPv4-адресов**;

- **Hardware size: 6:** Длина MAC-адреса составляет 6 байт;

- **Protocol size: 4:** Длина IPv4-адреса составляет 4 байта;

- **Opcode: request (1):** Это **запрос** (а не ответ). Код `1` означает ARP-request;

- **Sender MAC address: TPLink_cd:bd:ea (`6c:5a:b0:cd:bd:ea`)** - то есть на вопрос "Кто спрашивает?" можно ответить - устройство с MAC-адресом `6c:5a:b0:cd:bd:ea`. 

- **Sender IP address: 192.168.1.1** - а какой IP-адрес у того, кто спрашивает? - `192.168.1.1` это шлюз по умолчанию. Это означает, что отправитель - это мой маршрутизатор.

- **Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)** - какой MAC-адрес у того, кого ищут? - это поле заполнено нулями, потому что отправитель его не знает. Именно это он и пытается выяснить в данном запросе.

- **Target IP address: 192.168.1.105** - а кого пытается найти маршрутизатор? - он пытается найти устройство с IP-адресом **`192.168.1.105`**. Чтобы отправить пакет на шлюз, маршрутизатору и нужен его **MAC-адрес**. Поэтому маршрутизатор и  инициирует ARP-запрос, поскольку не нашёл MAC-адрес устройства в своей ARP-таблице.

Таким образом, при помощи программы tshark я перехватил штатный служебный broadcast-запрос от моего роутера TP-Link, который пытается найти в локальной сети устройство с адресом `192.168.1.105`, чтобы доставить ему данные.






