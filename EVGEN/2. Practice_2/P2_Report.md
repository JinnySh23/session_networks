# Практика №2

## Анализ и статистика пакетов в сети

Для начала анализа, узнаем имя своего активного интерфейса при помощи команды - **tshark -D**

```bash
C:\Windows\system32>tshark -D
1. \Device\NPF_{05274B42-D467-41CA-9BB5-9236A73721CB} (Подключение по локальной сети* 8)
2. \Device\NPF_{145C2113-74C2-48D6-984F-0B66AA09D04B} (Подключение по локальной сети* 7)
3. \Device\NPF_{BE0FEC35-5A3E-4B47-ABE2-7A10AE332A22} (Подключение по локальной сети* 6)
4. \Device\NPF_{AC924965-04C9-45E4-8CB5-C59F63778863} (Ethernet 3)
5. \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9} (Ethernet 2)
6. \Device\NPF_{7628CB59-858B-611E-93DA-01A31EEDD676} (neko-tun)
7. \Device\NPF_Loopback (Adapter for loopback traffic capture)
8. \Device\NPF_{8206B89A-3D8F-4386-AD83-47D954B9CF67} (Ethernet)
9. etwdump (Event Tracing for Windows (ETW) reader)
```

Я знаю, что в моём подключении используется адаптер Ethernet 2, следовательно его номер - **5**

Сейчас мы захватим 10 пакетов, чтобы не перегружать себя данными, и сразу посмотрим статистику по разговорам между IP адресами. Для этого пропишем такую команду: **tshark -i 5 -c 10 -q -z conv,ip**, где:

- -i 5 - номер нашего интерфейса;

- -c 10 - даст остановку после захвата 10 пакетов;

- -q - включаем "тихий режим", чтобы не выводить результат захвата сразу в реальном времени;

- -z conv,ip - для показа иерархической статистики по разговорам между IP адресами после завершения захвата;

```bash
Capturing on 'Ethernet 2'
10 packets captured
================================================================================
IPv4 Conversations
Filter:<No Filter>
                                               |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                               | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.1.112        <-> 192.168.1.104              3 757 bytes       3 755 bytes       6 1512 bytes     0,000000000         0,4117
192.168.1.112        <-> 239.255.255.250            0 0 bytes         1 179 bytes       1 179 bytes     0,067636000         0,0000
192.168.1.1          <-> 192.168.1.112              0 0 bytes         1 381 bytes       1 381 bytes     0,068469000         0,0000
192.168.1.112        <-> 149.154.167.51             0 0 bytes         1 399 bytes       1 399 bytes     1,049451000         0,0000
================================================================================
```

Разберём наш вывод:

- Заголовок **IPv4 Conversations** - это статистика IP-разговоров (conversations) без дополнительного фильтра.  Каждая строка — это пара узлов, между которыми шёл обмен пакетами;

- В первой строке мы видим `192.168.1.112` - IP адрес моего компьютера, который обменивается пакетами с устройством, IP которого во второй колонке;

- В третьей колонке **<- Frames Bytes** - количество кадров (пакетов) и байт в направлении **слева направо**. На примере первой строки 3 пакета и 757 байт было отправлено от моего компьютера к устройству;

- В четвёртой колонке **-> Frames Bytes** - наоборот, в направлении **справа налево**. На примере первой строки 3 пакета и 755 байт было отправлено с устройства с IP `192.168.1.104` на мой компьютер;

- В пятой колонке **Total Frames Bytes** - суммарное количество пакетов/байт в обе стороны. На примере первой строки, это 6 пакетов и 1512 байт;

- В шестой колонке **Relative Start** - время начала разговора относительно первого захваченного пакета. На примере первой строки это 0 секунд;

- В седьмой колонке **Duration** - это длительность разговора (от первого до последнего пакета). На примере первой строки это 0,4117 секунд.

По полученной статистике можно сделать вывод, что основная активность - локальный обмен данными между 192.168.1.112 и 192.168.1.104. Также были мультикаст-запросы SSDP (поиск устройств в сети). Есть общение с роутером (служебный трафик) - это видно по IP из третьей строки `192.168.1.1`. Был также замечен пакет на IP Telegram (внешняя связь) по IP из последней строки `149.154.167.51`. Почему именно Telegram? Это легко проверить, введя команду: **nslookup 149.154.167.1**

```bash
C:\Windows\system32>nslookup 149.154.167.1
╤хЁтхЁ:  UnKnown
Address:  172.19.0.2

╚ь :     mail-2-6.telegram.org
Address:  149.154.167.1
```

Из ответа мы видим, что диапазон данного IP адреса принадлежит **Telegram Messenger (MTProto)**.

Теперь выведем статистику по протоколам, воспользовавшись командой: **tshark -i 5 -c 10 -q -z io,phs**, где -z io,phs - для показа иерархической статистики по протоколам после завершения захвата.

```bash
C:\Windows\system32>tshark -i 5 -c 10 -q -z io,phs
Capturing on 'Ethernet 2'
10 packets captured

===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:10 bytes:1754
  ip                                     frames:9 bytes:1694
    udp                                  frames:3 bytes:930
      data                               frames:1 bytes:370
      ssdp                               frames:2 bytes:560
    tcp                                  frames:6 bytes:764
  arp                                    frames:1 bytes:60
===================================================================
```

Разберём данную **статистику по протоколам (Protocol Hierarchy Statistics)**:

- eth   frames:10 bytes:1754 - говорит, что всего захвачено **10 Ethernet-кадров** общим объёмом **1754 байта**;

- ip   frames:9 bytes:1694 - показывает, что 9 пакетов содержали **IP-трафик** (почти всё, кроме одного) размером **1694 байта**;

- udp   frames:3 bytes:930 - показывает, что 3 пакета было по UDP, всего **930 байт**. Из них:
  
  - `data` — 1 пакет (**370 байт**) с "сырыми" данными (просто нагрузка без распознанного протокола);
  
  - `ssdp` — 2 пакета (**560 байт**) — это **Simple Service Discovery Protocol** (мультикаст на 239.255.255.250, поиск устройств UPnP в сети);

- tcp   frames:6 bytes:764 - показывает, что по TCP протоколу было 6 TCP-пакетов, весом всего **764 байта**. В данной статистике нет детальной расшифровки (например, TLS, HTTP), значит это были "голые" TCP-сегменты или их не удалось распознать по 10 пакетам;

- arp   frames:1 bytes:60 - показывает, что 1 пакет был **ARP** (Address Resolution Protocol). Обычно это запрос/ответ для определения MAC-адреса устройства в локальной сети.

По данной статистике, можно сделать вывод, что 6 пакетов были **TCP** - это интернет или локальные подключения. 3 пакета были **UDP** (из них 2 — SSDP, 1 — просто данные). И 1 пакет был **ARP** (служебный, для работы сети). Видно активность поиска устройств в сети (SSDP) и какой-то TCP-обмен.

## Глубокий анализ протокола UDP

UDP не имеет выделенного порта как DNS (порт 53), поэтому мы можем захватывать трафик с разных портов. Давайте захватим первый попавшийся UDP-трафик при помощи команды: **tshark -i 5 -f "udp" -c 20 -w udp_capture.pcapng**, где при помощи -f отфильтруем трафик для UDP, а при помощи -w запишем наш результат в файл "udp_capture.pcapng"

Теперь после захвата посмотрим на результат при помощи команды: **tshark -r udp_capture.pcapng -V -Y "udp"**. Для примера возьмём Frame 2:

```bash
Frame 2: 86 bytes on wire (688 bits), 86 bytes captured (688 bits) on interface \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9}, id 0
    Section number: 1
    Interface id: 0 (\Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9})
        Interface name: \Device\NPF_{7BAC09AD-02C8-45D4-A19E-80B2B4A376A9}
        Interface description: Ethernet 2
    Encapsulation type: Ethernet (1)
    Arrival Time: Sep 10, 2025 16:07:43.534448000 RTZ 2 (зима)
    UTC Arrival Time: Sep 10, 2025 13:07:43.534448000 UTC
    Epoch Arrival Time: 1758546463.534448000
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 2.416776000 seconds]
    [Time delta from previous displayed frame: 2.416776000 seconds]
    [Time since reference or first frame: 2.416776000 seconds]
    Frame Number: 2
    Frame Length: 86 bytes (688 bits)
    Capture Length: 86 bytes (688 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:ip:udp:snmp]
Ethernet II, Src: TPLink_b4:2b:4b (00:31:92:b4:2b:4b), Dst: 06:eb:d8:88:b8:1f (06:eb:d8:88:b8:1f)
    Destination: 06:eb:d8:88:b8:1f (06:eb:d8:88:b8:1f)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Source: TPLink_b4:2b:4b (00:31:92:b4:2b:4b)
        .... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: IPv4 (0x0800)
    [Stream index: 1]
Internet Protocol Version 4, Src: 192.168.1.112, Dst: 192.168.1.104
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Differentiated Services Field: 0x00 (DSCP: CS0, ECN: Not-ECT)
        0000 00.. = Differentiated Services Codepoint: Default (0)
        .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    Total Length: 72
    Identification: 0x4b20 (19232)
    000. .... = Flags: 0x0
        0... .... = Reserved bit: Not set
        .0.. .... = Don't fragment: Not set
        ..0. .... = More fragments: Not set
    ...0 0000 0000 0000 = Fragment Offset: 0
    Time to Live: 64
    Protocol: UDP (17)
    Header Checksum: 0x0000 [validation disabled]
    [Header checksum status: Unverified]
    Source Address: 192.168.1.112
    Destination Address: 192.168.1.104
    [Stream index: 1]
User Datagram Protocol, Src Port: 62748, Dst Port: 161
    Source Port: 62748
    Destination Port: 161
    Length: 52
    Checksum: 0x846e [unverified]
    [Checksum Status: Unverified]
    [Stream index: 1]
    [Stream Packet Number: 1]
    [Timestamps]
        [Time since first frame: 0.000000000 seconds]
        [Time since previous frame: 0.000000000 seconds]
    UDP payload (44 bytes)
Simple Network Management Protocol
    version: version-1 (0)
    community: public
    data: get-request (0)
        get-request
            request-id: 1624
            error-status: noError (0)
            error-index: 0
            variable-bindings: 1 item
                1.3.6.1.2.1.43.5.1.1.2.1: Value (Null)
                    Object Name: 1.3.6.1.2.1.43.5.1.1.2.1 (iso.3.6.1.2.1.43.5.1.1.2.1)
                    Value (Null)
```

Разберём данный Frame:

- Верхний уровень **Frame 2**: 86 bytes on wire (688 bits), 86 bytes captured (688 bits):
  
  - Пакет занимает 86 байт на кабеле, захвачено полностью (capture length = frame length);
  
  - Интерфейс: `\Device\NPF_{...}` - это «Ethernet 2» на твоей машине;
  
  - **Arrival Time:** `Sep 10, 2025 16:07:43.534448000 RTZ 2 (зима)` - локальное время (Европа/Хельсинки в данном разговоре). UTC-время показано отдельно (прошу прощения, забыл отключить VPN);
  
  - `[Time delta from previous captured frame: 2.416776000 seconds]` - между предыдущим захваченным кадром и этим прошло 2.416776 с;
  
  - **Frame Number: 2** — второй захваченный пакет в сессии;
  
  - `[Protocols in frame: eth:ethertype:ip:udp:snmp]` — стек протоколов в этом кадре: Ethernet → IPv4 → UDP → SNMP;

- **Ethernet II**:
  
  - **Source MAC** `00:31:92:b4:2b:4b` - OUI `00:31:92` соответствует TP-Link (по строке можно видеть `TPLink_...`) - это модель моего роутера;
  
  - **Destination MAC** `06:eb:d8:88:b8:1f` - Wireshark отмечает у неё **LG bit = 1** (локально назначенный MAC - locally administered). Это значит, что младший бит в первом октете установлен - MAC не обязательно «фабричный», мог быть назначен программно (виртуальный интерфейс, адрес, назначенный ОС, или кастомный MAC);
  
  - IG bit = 0 - это одноадресный (unicast) кадр;
  
  - Тип 0x0800 → далее IPv4-пакет;

- **IPv4 заголовок**:
  
  - **IP-адреса**: 192.168.1.112 → 192.168.1.104 (локальная сеть);
  
  - **Total Length = 72** - это длина IP-пакета (включая IP-заголовок). С учётом Ethernet-заголовка размер на проводе 86 байт (Ethernet overhead + IP);
  
  - **Flags = 0, fragment offset = 0** — пакет не фрагментирован;
  
  - **TTL = 64** — обычное значение TTL для локальных/Unix/Windows хостов;
  
  - Заголовочный Checksum помечен как «Unverified» — в этом дампе проверка отключена/не выполнялась;

- **UDP**:
  
  - **Порт назначения 161** — это стандартный порт **SNMP** (Simple Network Management Protocol);
  
  - **Источник — 62748** — ephemeral (временный) порт у запроса-инициатора;
  
  - Длина UDP полезной нагрузки 52 байта (включая SNMP);

- **SNMP (Simple Network Management Protocol)**:
  
  - **SNMPv1 get-request**: хост `192.168.1.112` отправляет **запрос GET** на `192.168.1.104`, со строкой `public`;
  
  - **community = public** - очень распространённая (и небезопасная) строка по умолчанию; часто используют в простых системах мониторинга;
  
  - **request-id = 1624** — идентификатор запроса, нужен для сопоставления ответа;
  
  - **variable-bindings** содержит один OID: `1.3.6.1.2.1.43.5.1.1.2.1`. Значение в этом пакете - `Null` (обычно потому, что это GET-запрос: запрашивается значение, а ответ придёт отдельным SNMP get-response с фактическим значением);
  
  - OID `1.3.6.1.2.1.43...` - это часть **Printer MIB**/MIB-2 (OID с префиксом 1.3.6.1.2.1 - standard MIB-2; ветка .43 - принтеры). То есть, судя по OID, запрос, вероятно, адресован к устройству, поддерживающему Printer MIB (принтер/мфу или агент от SNMP, который реализует эти объекты).
  
  Судя по данному анализу, можно сделать вывод, что мой компьютер мониторинга (`192.168.1.112`) **делает SNMP-запрос** к устройству `192.168.1.104` (вероятно, сетевой принтер или сетевой агент), спрашивая конкретный MIB-объект (вероятно относящийся к Printer MIB). Это **get-request**, поэтому в этом пакете никакого значения ещё нет — ответ ожидается в отдельном пакете (get-response) от `192.168.1.104` к `192.168.1.112` с таким же request-id. Тут используется SNMPv1 и «public» community — если это не должно быть публично доступным, мне наверное стоит задуматься о смене community или ограничении доступа по IP, так как community в SNMPv1 передаётся в открытом виде.
