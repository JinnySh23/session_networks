# Отчёт по базовым сетевым утилитам

## **PING**

**PING** (Packet InterNet Groper) - это сетевая утилита, предназначенная для проверки **достижимости** узла в сети и измерения **времени задержки** (latency) при передаче пакетов данных. Она используется для базовой диагностики сети, при проблемах с доступом к сайту или серверу его можно пропинговать. Также этой утилитой можно проверить качество соединения, например, высокое время отклика или потеря пакетов указывают на нестабильность канала связи. Эта утилита может выявлять проблема с DNS, к примеру, если пинг по доменному имени (например, google.com) проходит, а по IP-адресу — нет, это может указывать на проблемы, связанные с DNS.

<u>**Принцип работы:**</u>

Принцип работы утилиты ping основан на использовании протокола **ICMP** (Internet Control Message Protocol) - это вспомогательный протокол, который использует сетевые устройства (маршрутизаторы, серверы) для обмена служебной информацией.

Как работает утилита ping:

- Ваш компьютер формирует специальный ICMP-пакет типа **"Echo Request"** (Эхо-запрос);

- Затем в этот пакет помещается служебная информация, а также **метка времени** (timestamp) и **порядковый номер** (sequence number);

- Далее этот пакет отправляется целевому узлу по указанному IP-адресу или доменному имени (которое предварительно преобразуется в IP через DNS);

Заметим, что при этом пакет путешествует по сети через цепочку маршрутизаторов (роутеров) к целевому узлу. Но сама утилита ping не контролирует этот путь.

- Если целевой узел доступен и не блокирует ICMP-пакеты, он получает ваш "Echo Request";

- В соответствии со стандартами протокола ICMP, узел **обязан** ответить на такой запрос. Он формирует ответный ICMP-пакет типа **"Echo Reply"** (Эхо-ответ) и отправляет его обратно по тому же пути (или по другому пути, в зависимости от таблиц маршрутизации);

- По итогу, если всё хорошо, ваш компьютер получает ответный пакет "Echo Reply";

- Далее утилита `ping вычисляет **время круговой задержки (round-trip time, RTT)**- это время между отправкой запроса и получением ответа. Оно измеряется в миллисекундах (мс);

- Ну, а после, на экран выводится информация о полученном ответе: размер пакета, IP-адрес источника, порядковый номер и время отклика;

- Процесс повторяется несколько раз, в Windows по умолчанию 4 раза (4 пакета), а в Linux/macOS, пока вы не остановите процесс командой `Ctrl+C`);

- После завершения работы утилита выводит **статистику**: сколько пакетов было отправлено, получено, потеряно (%), а также минимальное, максимальное и среднее время задержки;

Проверим работу утилиты на примере команды: **ping google.com**

**Вывод:**

```bash
serg@serg-pc:~$ ping google.com
]PING google.com (173.194.221.139) 56(84) bytes of data.
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=1 ttl=255 time=13.2 ms
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=2 ttl=255 time=12.5 ms
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=3 ttl=255 time=12.5 ms
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=4 ttl=255 time=13.1 ms
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=5 ttl=255 time=12.8 ms
64 bytes from lm-in-f139.1e100.net (173.194.221.139): icmp_seq=6 ttl=255 time=12.6 ms
^C
--- google.com ping statistics ---
6 packets transmitted, 6 received, 0% packet loss, time 5053ms
rtt min/avg/max/mdev = 12.477/12.778/13.198/0.279 ms

```

Как видим, по результату 6 пакетов было отправлено, 6 ответов было получено, 0% пакетов потеряно, что говорит о хорошей стабильной связи, а время:

- 12.477 мс - минимальное время задержки из всех 6 отправленных пакетов. Самый быстрый ответ;

- 12.788 мс - среднее время задержки;

- 13.198 мс - максимальное время задержки из всех 6 отправленных пакетов. Самый медленный ответ;

- 0.279 мс - это среднеквадратичное отклонение (Standard Deviation). Это очень важный показатель стабильности. Он показывает, насколько сильно время отклика отклонялось от среднего значения (avg). В данном случае время 0.279 мс означает, что все пакеты шли с практически одинаковой задержкой. Соединение очень стабильное (джиттер почти отсутствует);

Можно модифицировать нашу команду, если мы хотим отправлять конкретное количество пакетов, указав флаг -c и число: **ping -c 9 google.com** (Отправим 9 пакетов). Также можно добавить ключ с -4 для проверки только по протоколу IPv4 или -6 для IPv6 соответственно.

## netstat

Утилита **netstat** (сокр. от *network statistics*) — это одна из ключевых сетевых утилит командной строки. Она предназначена для всестороннего анализа сетевых подключений и статистики сети. 

Данная утилита показывает:

- Какие программы куда подключены и откуда подключаются к вам (входящие соединения);

- Какие порты прослушиваются;

- Сколько данных отправлено и получено, есть ли ошибки;

- По каким путям пакеты уходят из вашей системы в другие сети (включая интернет);

Также утилита предоставляет статистику по сетевым протоколам: IPv4, IPv6, ICMP, TCP, UDP.

Принцип работы утилиты netstat заключается в **чтении и анализе различных системных файлов и структур ядра Linux**, которые хранят всю информацию о сетевой активности. Сама утилита не "следит" за сетью в реальном времени, а лишь запрашивает и красиво отображает уже собранные системой данные.

Такие каталоги, как `/proc/net/tcp` и `/proc/net/udp` - содержат виртуальные файлы в псевдо-файловой системе `/proc`, которые содержат подробнейшую информацию о всех TCP и UDP сокетах (порты, состояние, IP-адреса, Inode и т.д.). Это основной источник данных для вывода списка соединений.

Файл `/proc/net/dev` содержит статистику по всем сетевым интерфейсам (eth0, wlan0 и др.) — количество байт, пакетов, ошибок.

А чтобы показать, какой процесс использует соединение, утилита **netstat** (с ключом `-p`) ищет соответствие между номером сокета (Inode) из `/proc/net/tcp` и списком открытых файлов каждого процесса в каталоге `/proc/<PID>/fd/`, таким образом предоставляя нам PID процесса и его соединения.

В случае маршрутизации ядра, утилита netstat запрашивает у ядра информацию о том, куда отправляются пакеты для разных сетей.

Для того, чтобы показать все активные подключения, введём команду: **netstat -a**

```bash
serg@serg-pc:~$ netstat -a
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 _localdnsproxy:domain   0.0.0.0:*               LISTEN     
tcp        0      0 _localdnsstub:domain    0.0.0.0:*               LISTEN     
tcp        0      0 localhost:ipp           0.0.0.0:*               LISTEN     
tcp6       0      0 ip6-localhost:ipp       [::]:*                  LISTEN     
udp        0      0 0.0.0.0:56999           0.0.0.0:*                          
udp        0      0 _localdnsproxy:domain   0.0.0.0:*                          
udp        0      0 _localdnsstub:domain    0.0.0.0:*                          
udp        0      0 serg-pc:bootpc          _gateway:bootps         ESTABLISHED
udp        0      0 0.0.0.0:mdns            0.0.0.0:*                          
udp6       0      0 [::]:mdns               [::]:*                             
udp6       0      0 [::]:42732              [::]:*                             
raw6       0      0 [::]:ipv6-icmp          [::]:*                  7          
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  3      [ ]         STREAM     CONNECTED     13518    
unix  3      [ ]         STREAM     CONNECTED     12456    
unix  3      [ ]         STREAM     CONNECTED     12480    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10259    
unix  3      [ ]         STREAM     CONNECTED     11749    
unix  3      [ ]         STREAM     CONNECTED     13479    
unix  3      [ ]         STREAM     CONNECTED     13454    
unix  3      [ ]         STREAM     CONNECTED     12497    
unix  3      [ ]         STREAM     CONNECTED     11604    
unix  3      [ ]         STREAM     CONNECTED     7764     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14548    /run/user/1000/bus
unix  2      [ ]         DGRAM      CONNECTED     8818     
unix  2      [ ]         DGRAM      CONNECTED     5455     
unix  2      [ ]         DGRAM      CONNECTED     7752     
unix  3      [ ]         STREAM     CONNECTED     13472    
unix  3      [ ]         STREAM     CONNECTED     11760    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11654    
unix  3      [ ]         STREAM     CONNECTED     11145    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     13514    
unix  3      [ ]         STREAM     CONNECTED     11633    
unix  3      [ ]         STREAM     CONNECTED     12443    
unix  3      [ ]         STREAM     CONNECTED     7772     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     13329    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10152    
unix  3      [ ]         STREAM     CONNECTED     13459    
unix  3      [ ]         STREAM     CONNECTED     11606    
unix  3      [ ]         STREAM     CONNECTED     7763     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     7759     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11861    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10205    /run/user/1000/bus
unix  2      [ ]         DGRAM      CONNECTED     5896     
unix  3      [ ]         STREAM     CONNECTED     20090    
unix  3      [ ]         STREAM     CONNECTED     13432    
unix  3      [ ]         STREAM     CONNECTED     11666    
unix  3      [ ]         STREAM     CONNECTED     12459    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14520    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12486    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11574    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     7079     
unix  3      [ ]         STREAM     CONNECTED     14490    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14388    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10154    
unix  3      [ ]         STREAM     CONNECTED     8766     
unix  2      [ ]         DGRAM      CONNECTED     7736     
unix  3      [ ]         STREAM     CONNECTED     11778    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11594    
unix  3      [ ]         STREAM     CONNECTED     14559    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10240    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     5642     /run/systemd/io.systemd.sysext
unix  3      [ ]         STREAM     CONNECTED     13457    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11685    
unix  3      [ ]         STREAM     CONNECTED     12487    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     8767     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12490    
unix  3      [ ]         STREAM     CONNECTED     11226    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     7753     
unix  3      [ ]         STREAM     CONNECTED     13433    /run/user/1000/pipewire-0
unix  3      [ ]         STREAM     CONNECTED     12534    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     10168    
unix  3      [ ]         DGRAM      CONNECTED     10935    
unix  2      [ ]         DGRAM      CONNECTED     13502    
unix  3      [ ]         STREAM     CONNECTED     11623    
unix  3      [ ]         STREAM     CONNECTED     12491    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     7159     
unix  3      [ ]         STREAM     CONNECTED     8699     
unix  3      [ ]         STREAM     CONNECTED     13405    
unix  3      [ ]         STREAM     CONNECTED     11667    
unix  3      [ ]         STREAM     CONNECTED     11206    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     13516    
unix  3      [ ]         STREAM     CONNECTED     7765     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14340    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11605    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11828    
unix  3      [ ]         STREAM     CONNECTED     10184    
unix  3      [ ]         STREAM     CONNECTED     13451    
unix  3      [ ]         STREAM     CONNECTED     11656    
unix  3      [ ]         STREAM     CONNECTED     10795    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11651    
unix  3      [ ]         STREAM     CONNECTED     12775    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10214    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10246    
unix  3      [ ]         STREAM     CONNECTED     13452    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11759    
unix  3      [ ]         STREAM     CONNECTED     11680    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     5794     
unix  3      [ ]         DGRAM      CONNECTED     5351     
unix  3      [ ]         STREAM     CONNECTED     13498    
unix  3      [ ]         STREAM     CONNECTED     10204    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12458    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM      CONNECTED     8789     
unix  3      [ ]         STREAM     CONNECTED     7084     
unix  3      [ ]         STREAM     CONNECTED     7683     
unix  3      [ ]         STREAM     CONNECTED     12711    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14430    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11679    
unix  3      [ ]         STREAM     CONNECTED     11185    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14557    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     10203    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11573    
unix  3      [ ]         STREAM     CONNECTED     11544    /run/user/1000/bus
unix  3      [ ]         DGRAM      CONNECTED     9274     
unix  3      [ ]         STREAM     CONNECTED     14511    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     14481    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10125    
unix  2      [ ACC ]     STREAM     LISTENING     10799    /tmp/.iprt-localipc-DRMIpcServer
unix  3      [ ]         STREAM     CONNECTED     13519    
unix  3      [ ]         STREAM     CONNECTED     12492    
unix  3      [ ]         STREAM     CONNECTED     11621    
unix  3      [ ]         STREAM     CONNECTED     8800     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10220    /run/user/1000/at-spi/bus_0
unix  3      [ ]         DGRAM      CONNECTED     5352     
unix  3      [ ]         STREAM     CONNECTED     21813    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12405    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     7760     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12523    
unix  3      [ ]         STREAM     CONNECTED     11620    
unix  3      [ ]         STREAM     CONNECTED     7762     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11873    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     9273     
unix  3      [ ]         STREAM     CONNECTED     10086    
unix  2      [ ]         DGRAM                    10245    
unix  3      [ ]         STREAM     CONNECTED     13474    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11693    
unix  3      [ ]         STREAM     CONNECTED     13484    
unix  3      [ ]         STREAM     CONNECTED     12510    
unix  3      [ ]         STREAM     CONNECTED     11246    @/tmp/.ICE-unix/1190
unix  3      [ ]         STREAM     CONNECTED     12537    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10201    
unix  3      [ ]         STREAM     CONNECTED     13456    
unix  3      [ ]         STREAM     CONNECTED     7761     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     4949     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     13497    
unix  3      [ ]         STREAM     CONNECTED     12469    
unix  3      [ ]         STREAM     CONNECTED     8819     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10202    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     7754     
unix  3      [ ]         STREAM     CONNECTED     11777    
unix  3      [ ]         STREAM     CONNECTED     11765    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10219    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     9056     
unix  3      [ ]         STREAM     CONNECTED     8702     
unix  3      [ ]         STREAM     CONNECTED     12441    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11421    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14452    
unix  3      [ ]         STREAM     CONNECTED     14420    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     9879     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13557    
unix  3      [ ]         STREAM     CONNECTED     14546    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     12596    
unix  3      [ ]         STREAM     CONNECTED     3013     
unix  2      [ ]         DGRAM      CONNECTED     10924    
unix  3      [ ]         STREAM     CONNECTED     10074    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11349    
unix  3      [ ]         STREAM     CONNECTED     12763    
unix  3      [ ]         STREAM     CONNECTED     12601    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11682    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     8641     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     13571    
unix  3      [ ]         STREAM     CONNECTED     11773    /run/user/1000/at-spi/bus_0
unix  2      [ ]         DGRAM                    13536    
unix  3      [ ]         STREAM     CONNECTED     14385    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11914    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11768    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12593    
unix  3      [ ]         STREAM     CONNECTED     10830    
unix  3      [ ]         STREAM     CONNECTED     7659     
unix  3      [ ]         STREAM     CONNECTED     11004    
unix  2      [ ACC ]     STREAM     LISTENING     11330    /tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     10187    /tmp/.ICE-unix/1190
unix  3      [ ]         STREAM     CONNECTED     11529    
unix  2      [ ]         DGRAM                    10934    /run/user/1000/systemd/notify
unix  3      [ ]         STREAM     CONNECTED     12806    
unix  3      [ ]         STREAM     CONNECTED     12780    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     14414    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     10937    /run/user/1000/systemd/private
unix  3      [ ]         STREAM     CONNECTED     12665    
unix  3      [ ]         STREAM     CONNECTED     11769    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11572    
unix  2      [ ACC ]     STREAM     LISTENING     10946    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10866    
unix  3      [ ]         STREAM     CONNECTED     13528    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12764    
unix  3      [ ]         STREAM     CONNECTED     12663    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14454    
unix  2      [ ACC ]     STREAM     LISTENING     10947    /run/user/1000/gnupg/S.dirmngr
unix  2      [ ]         DGRAM      CONNECTED     11360    
unix  3      [ ]         STREAM     CONNECTED     13321    
unix  2      [ ]         DGRAM      CONNECTED     11235    
unix  3      [ ]         STREAM     CONNECTED     11549    
unix  3      [ ]         STREAM     CONNECTED     10816    
unix  2      [ ACC ]     STREAM     LISTENING     10949    /run/user/1000/gcr/ssh
unix  3      [ ]         STREAM     CONNECTED     11405    
unix  3      [ ]         STREAM     CONNECTED     12832    
unix  3      [ ]         STREAM     CONNECTED     13480    
unix  3      [ ]         STREAM     CONNECTED     13419    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12462    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     10951    /run/user/1000/keyring/control
unix  3      [ ]         STREAM     CONNECTED     13553    
unix  3      [ ]         STREAM     CONNECTED     13376    
unix  2      [ ACC ]     STREAM     LISTENING     10953    /run/user/1000/gnupg/S.gpg-agent.browser
unix  2      [ ]         STREAM     CONNECTED     10862    
unix  3      [ ]         STREAM     CONNECTED     11484    /run/user/1000/pipewire-0
unix  2      [ ACC ]     STREAM     LISTENING     10955    /run/user/1000/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     6897     /run/systemd/resolve/io.systemd.Resolve
unix  3      [ ]         STREAM     CONNECTED     12845    @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     10957    /run/user/1000/gnupg/S.gpg-agent
unix  3      [ ]         STREAM     CONNECTED     9723     /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     6898     /run/systemd/resolve/io.systemd.Resolve.Monitor
unix  3      [ ]         STREAM     CONNECTED     22753    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11902    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12625    
unix  3      [ ]         STREAM     CONNECTED     13331    
unix  2      [ ACC ]     STREAM     LISTENING     10959    /run/user/1000/gnupg/S.keyboxd
unix  3      [ ]         STREAM     CONNECTED     2682     
unix  2      [ ]         DGRAM      CONNECTED     2688     
unix  3      [ ]         STREAM     CONNECTED     11475    
unix  2      [ ACC ]     STREAM     LISTENING     10961    /run/user/1000/pulse/native
unix  3      [ ]         STREAM     CONNECTED     13363    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12542    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     10963    /run/user/1000/pipewire-0
unix  2      [ ACC ]     STREAM     LISTENING     9265     /run/avahi-daemon/socket
unix  3      [ ]         STREAM     CONNECTED     11915    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     13527    
unix  3      [ ]         STREAM     CONNECTED     13481    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     10965    /run/user/1000/pipewire-0-manager
unix  3      [ ]         STREAM     CONNECTED     10814    
unix  2      [ ACC ]     STREAM     LISTENING     10967    /run/user/1000/pk-debconf-socket
unix  2      [ ]         DGRAM      CONNECTED     7615     
unix  2      [ ACC ]     STREAM     LISTENING     9266     /run/cups/cups.sock
unix  2      [ ACC ]     STREAM     LISTENING     9268     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12606    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12576    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     10969    /run/user/1000/speech-dispatcher/speechd.sock
unix  3      [ ]         STREAM     CONNECTED     9100     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14643    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13525    
unix  3      [ ]         STREAM     CONNECTED     11772    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     10977    /run/user/1000/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     9269     /run/uuidd/request
unix  3      [ ]         DGRAM      CONNECTED     2693     
unix  3      [ ]         STREAM     CONNECTED     13554    /run/user/1000/gvfsd/socket-5V6CAhck
unix  3      [ ]         STREAM     CONNECTED     14456    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     14451    
unix  2      [ ]         DGRAM                    11486    
unix  3      [ ]         STREAM     CONNECTED     14717    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     12600    
unix  3      [ ]         STREAM     CONNECTED     10749    
unix  3      [ ]         STREAM     CONNECTED     9805     /tmp/.iprt-localipc-DRMIpcServer
unix  3      [ ]         STREAM     CONNECTED     11423    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     20072    
unix  3      [ ]         STREAM     CONNECTED     12910    
unix  3      [ ]         STREAM     CONNECTED     12597    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     9300     /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     20135    /var/lib/fwupd/gnupg/S.gpg-agent
unix  3      [ ]         STREAM     CONNECTED     13524    
unix  3      [ ]         STREAM     CONNECTED     12666    
unix  2      [ ACC ]     STREAM     LISTENING     20136    /var/lib/fwupd/gnupg/S.gpg-agent.extra
unix  3      [ ]         STREAM     CONNECTED     11044    
unix  3      [ ]         STREAM     CONNECTED     10069    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     20137    /var/lib/fwupd/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     20138    /var/lib/fwupd/gnupg/S.gpg-agent.ssh
unix  3      [ ]         STREAM     CONNECTED     12776    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12761    
unix  3      [ ]         STREAM     CONNECTED     14450    
unix  3      [ ]         STREAM     CONNECTED     12594    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     9107     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     13362    
unix  3      [ ]         STREAM     CONNECTED     7583     
unix  2      [ ]         DGRAM      CONNECTED     10917    
unix  3      [ ]         DGRAM      CONNECTED     2692     
unix  3      [ ]         STREAM     CONNECTED     14650    /run/user/1000/gvfsd/socket-2CuADZDd
unix  3      [ ]         STREAM     CONNECTED     12835    
unix  3      [ ]         STREAM     CONNECTED     11732    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     14449    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12619    
unix  2      [ ]         DGRAM                    19745    
unix  2      [ ACC ]     STREAM     LISTENING     11567    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     4530     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11860    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12605    
unix  3      [ ]         STREAM     CONNECTED     13348    
unix  3      [ ]         STREAM     CONNECTED     9169     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12834    
unix  3      [ ]         STREAM     CONNECTED     14474    
unix  3      [ ]         STREAM     CONNECTED     14343    @/tmp/.ICE-unix/1190
unix  3      [ ]         STREAM     CONNECTED     13521    
unix  3      [ ]         STREAM     CONNECTED     12649    
unix  2      [ ACC ]     STREAM     LISTENING     11232    /run/user/1000/keyring/pkcs11
unix  2      [ ACC ]     STREAM     LISTENING     11234    /run/user/1000/keyring/ssh
unix  3      [ ]         STREAM     CONNECTED     11479    
unix  3      [ ]         STREAM     CONNECTED     12783    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     9070     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     4948     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11859    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11789    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12661    
unix  3      [ ]         STREAM     CONNECTED     13327    
unix  3      [ ]         STREAM     CONNECTED     10238    
unix  3      [ ]         STREAM     CONNECTED     11833    
unix  3      [ ]         STREAM     CONNECTED     14342    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12408    /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM      CONNECTED     9442     
unix  3      [ ]         STREAM     CONNECTED     13316    
unix  3      [ ]         STREAM     CONNECTED     12367    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13588    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14603    
unix  3      [ ]         STREAM     CONNECTED     14393    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     5071     
unix  3      [ ]         STREAM     CONNECTED     13483    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12546    
unix  3      [ ]         STREAM     CONNECTED     11209    
unix  3      [ ]         STREAM     CONNECTED     11694    
unix  3      [ ]         STREAM     CONNECTED     11239    
unix  3      [ ]         STREAM     CONNECTED     14594    
unix  3      [ ]         STREAM     CONNECTED     10006    
unix  3      [ ]         STREAM     CONNECTED     7775     /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     6973     /run/irqbalance/irqbalance624.sock
unix  3      [ ]         DGRAM      CONNECTED     5070     
unix  3      [ ]         STREAM     CONNECTED     10236    
unix  3      [ ]         STREAM     CONNECTED     10215    
unix  3      [ ]         STREAM     CONNECTED     11832    
unix  3      [ ]         STREAM     CONNECTED     14341    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     9750     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     19518    
unix  3      [ ]         STREAM     CONNECTED     14523    
unix  3      [ ]         STREAM     CONNECTED     14392    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10208    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11858    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12551    
unix  3      [ ]         STREAM     CONNECTED     11155    
unix  2      [ ]         DGRAM      CONNECTED     10004    
unix  3      [ ]         STREAM     CONNECTED     12043    
unix  3      [ ]         STREAM     CONNECTED     12808    /tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     11699    
unix  3      [ ]         STREAM     CONNECTED     11242    
unix  2      [ ]         DGRAM      CONNECTED     5048     
unix  3      [ ]         STREAM     CONNECTED     11839    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12547    
unix  3      [ ]         STREAM     CONNECTED     11139    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     13540    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14447    
unix  3      [ ]         STREAM     CONNECTED     12402    /run/user/1000/pipewire-0
unix  3      [ ]         STREAM     CONNECTED     9422     
unix  3      [ ]         STREAM     CONNECTED     14670    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12494    /run/user/1000/bus
unix  3      [ ]         DGRAM      CONNECTED     5069     
unix  3      [ ]         STREAM     CONNECTED     14627    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12530    
unix  3      [ ]         STREAM     CONNECTED     11250    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     13538    /run/user/1000/pipewire-0
unix  3      [ ]         STREAM     CONNECTED     11703    
unix  3      [ ]         STREAM     CONNECTED     11437    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13589    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12525    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     8661     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11184    
unix  3      [ ]         STREAM     CONNECTED     19520    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11863    
unix  3      [ ]         STREAM     CONNECTED     11674    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM      CONNECTED     9517     
unix  3      [ ]         STREAM     CONNECTED     9301     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12042    
unix  3      [ ]         STREAM     CONNECTED     11886    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12403    /run/user/1000/pipewire-0
unix  3      [ ]         STREAM     CONNECTED     14391    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11668    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     18161    
unix  3      [ ]         STREAM     CONNECTED     13499    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     8551     
unix  3      [ ]         STREAM     CONNECTED     14518    /run/user/1000/pulse/native
unix  3      [ ]         STREAM     CONNECTED     12440    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     19519    
unix  3      [ ]         STREAM     CONNECTED     14448    
unix  3      [ ]         STREAM     CONNECTED     14604    
unix  3      [ ]         STREAM     CONNECTED     12495    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11841    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11077    
unix  3      [ ]         STREAM     CONNECTED     12742    /run/user/1000/pipewire-0
unix  2      [ ]         DGRAM                    9458     
unix  3      [ ]         STREAM     CONNECTED     7757     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11698    
unix  3      [ ]         STREAM     CONNECTED     11244    
unix  3      [ ]         STREAM     CONNECTED     12848    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14575    
unix  3      [ ]         STREAM     CONNECTED     10015    
unix  3      [ ]         STREAM     CONNECTED     12740    
unix  3      [ ]         STREAM     CONNECTED     11837    
unix  3      [ ]         STREAM     CONNECTED     10216    /run/user/1000/pipewire-0
unix  3      [ ]         DGRAM      CONNECTED     5350     /run/systemd/notify
unix  3      [ ]         STREAM     CONNECTED     13314    
unix  3      [ ]         STREAM     CONNECTED     11438    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     9551     
unix  2      [ ACC ]     STREAM     LISTENING     5353     /run/systemd/private
unix  3      [ ]         STREAM     CONNECTED     14524    
unix  3      [ ]         STREAM     CONNECTED     12579    @/tmp/.X11-unix/X0
unix  3      [ ]         DGRAM      CONNECTED     10936    
unix  3      [ ]         STREAM     CONNECTED     12741    
unix  3      [ ]         STREAM     CONNECTED     14498    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     5355     /run/systemd/userdb/io.systemd.DynamicUser
unix  3      [ ]         STREAM     CONNECTED     11659    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     10130    @/tmp/.X11-unix/X0
unix  2      [ ACC ]     STREAM     LISTENING     5356     /run/systemd/io.systemd.ManagedOOM
unix  3      [ ]         STREAM     CONNECTED     12080    
unix  3      [ ]         STREAM     CONNECTED     11708    
unix  3      [ ]         STREAM     CONNECTED     11240    
unix  3      [ ]         STREAM     CONNECTED     14593    
unix  3      [ ]         STREAM     CONNECTED     10005    
unix  3      [ ]         STREAM     CONNECTED     14497    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12531    
unix  3      [ ]         STREAM     CONNECTED     9749     
unix  3      [ ]         STREAM     CONNECTED     12508    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    11236    
unix  3      [ ]         STREAM     CONNECTED     10188    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11834    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11704    
unix  3      [ ]         STREAM     CONNECTED     10085    
unix  2      [ ACC ]     STREAM     LISTENING     3866     /run/lvm/lvmpolld.socket
unix  3      [ ]         STREAM     CONNECTED     12758    
unix  3      [ ]         STREAM     CONNECTED     11856    
unix  3      [ ]         STREAM     CONNECTED     12485    /run/user/1000/at-spi/bus_0
unix  2      [ ]         DGRAM                    3868     /run/systemd/journal/syslog
unix  3      [ ]         STREAM     CONNECTED     13320    
unix  2      [ ACC ]     SEQPACKET  LISTENING     3870     /run/systemd/coredump
unix  3      [ ]         STREAM     CONNECTED     18156    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     14513    
unix  3      [ ]         STREAM     CONNECTED     14390    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10035    
unix  2      [ ACC ]     STREAM     LISTENING     3872     /run/systemd/fsck.progress
unix  3      [ ]         STREAM     CONNECTED     11223    
unix  3      [ ]         STREAM     CONNECTED     8536     
unix  3      [ ]         STREAM     CONNECTED     11840    
unix  3      [ ]         STREAM     CONNECTED     11673    /run/systemd/journal/stdout
unix  16     [ ]         DGRAM      CONNECTED     3874     /run/systemd/journal/dev-log
unix  3      [ ]         STREAM     CONNECTED     11980    
unix  3      [ ]         STREAM     CONNECTED     9518     
unix  8      [ ]         DGRAM      CONNECTED     3876     /run/systemd/journal/socket
unix  3      [ ]         STREAM     CONNECTED     11751    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11648    /run/user/1000/pulse/native
unix  2      [ ACC ]     STREAM     LISTENING     3878     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12739    
unix  3      [ ]         STREAM     CONNECTED     10218    
unix  2      [ ACC ]     SEQPACKET  LISTENING     3880     /run/udev/control
unix  3      [ ]         STREAM     CONNECTED     14626    
unix  3      [ ]         STREAM     CONNECTED     12082    
unix  3      [ ]         STREAM     CONNECTED     13542    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     18159    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11767    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     13315    @/tmp/.ICE-unix/1190
unix  2      [ ]         DGRAM      CONNECTED     11211    
unix  3      [ ]         STREAM     CONNECTED     10018    
unix  3      [ ]         DGRAM      CONNECTED     5068     
unix  3      [ ]         STREAM     CONNECTED     11138    
unix  3      [ ]         STREAM     CONNECTED     11838    
unix  3      [ ]         STREAM     CONNECTED     11672    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     8537     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11978    
unix  3      [ ]         STREAM     CONNECTED     13319    
unix  3      [ ]         STREAM     CONNECTED     14389    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     10084    
unix  3      [ ]         STREAM     CONNECTED     8752     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12914    
unix  3      [ ]         STREAM     CONNECTED     11924    /run/user/1000/bus
unix  2      [ ]         DGRAM                    12718    
unix  3      [ ]         STREAM     CONNECTED     12589    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     8571     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11727    
unix  3      [ ]         STREAM     CONNECTED     14404    
unix  3      [ ]         STREAM     CONNECTED     9878     
unix  3      [ ]         STREAM     CONNECTED     12369    
unix  3      [ ]         STREAM     CONNECTED     11883    
unix  3      [ ]         STREAM     CONNECTED     12585    
unix  3      [ ]         STREAM     CONNECTED     7642     /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    14423    
unix  3      [ ]         STREAM     CONNECTED     11801    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12368    
unix  3      [ ]         STREAM     CONNECTED     11422    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14647    
unix  3      [ ]         STREAM     CONNECTED     12559    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14408    
unix  3      [ ]         STREAM     CONNECTED     11726    
unix  3      [ ]         STREAM     CONNECTED     9989     
unix  3      [ ]         STREAM     CONNECTED     9165     
unix  3      [ ]         STREAM     CONNECTED     11888    
unix  3      [ ]         STREAM     CONNECTED     12552    
unix  3      [ ]         STREAM     CONNECTED     11534    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     7043     
unix  3      [ ]         STREAM     CONNECTED     12683    
unix  3      [ ]         STREAM     CONNECTED     13349    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12439    
unix  3      [ ]         STREAM     CONNECTED     10070    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11885    
unix  3      [ ]         STREAM     CONNECTED     12578    
unix  3      [ ]         STREAM     CONNECTED     8633     
unix  2      [ ACC ]     STREAM     LISTENING     5452     /run/systemd/journal/io.systemd.journal
unix  3      [ ]         STREAM     CONNECTED     14429    
unix  3      [ ]         STREAM     CONNECTED     11041    
unix  3      [ ]         STREAM     CONNECTED     12668    
unix  3      [ ]         STREAM     CONNECTED     12591    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     9067     
unix  3      [ ]         STREAM     CONNECTED     12558    
unix  3      [ ]         STREAM     CONNECTED     14552    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     14432    
unix  3      [ ]         STREAM     CONNECTED     11424    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     9928     
unix  2      [ ]         DGRAM      CONNECTED     8586     
unix  3      [ ]         STREAM     CONNECTED     13357    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14578    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11675    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     8703     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     8672     
unix  3      [ ]         STREAM     CONNECTED     13439    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     14405    
unix  3      [ ]         STREAM     CONNECTED     11436    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11273    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11903    
unix  3      [ ]         STREAM     CONNECTED     12557    
unix  3      [ ]         STREAM     CONNECTED     8671     
unix  3      [ ]         STREAM     CONNECTED     19521    @/tmp/.ICE-unix/1190
unix  3      [ ]         STREAM     CONNECTED     11425    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12341    
unix  3      [ ]         DGRAM      CONNECTED     12375    
unix  3      [ ]         STREAM     CONNECTED     8656     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     12586    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     12671    
unix  3      [ ]         STREAM     CONNECTED     12602    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     13350    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11870    
unix  3      [ ]         STREAM     CONNECTED     12913    
unix  3      [ ]         STREAM     CONNECTED     11678    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     14403    
unix  3      [ ]         STREAM     CONNECTED     10863    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     9785     
unix  3      [ ]         STREAM     CONNECTED     12738    
unix  3      [ ]         STREAM     CONNECTED     11869    
unix  3      [ ]         STREAM     CONNECTED     12561    
unix  3      [ ]         STREAM     CONNECTED     7756     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11827    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     9906     @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     12629    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     12583    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     10012    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     6971     
unix  3      [ ]         STREAM     CONNECTED     11783    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     8655     
unix  3      [ ]         STREAM     CONNECTED     11432    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     9980     
unix  3      [ ]         STREAM     CONNECTED     12735    
unix  3      [ ]         STREAM     CONNECTED     14409    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     13359    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     12588    
unix  3      [ ]         STREAM     CONNECTED     11142    @/tmp/.X11-unix/X0
unix  3      [ ]         DGRAM      CONNECTED     12376    
unix  3      [ ]         STREAM     CONNECTED     12810    /tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     9945     /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13430    /run/user/1000/pulse/native
unix  3      [ ]         STREAM     CONNECTED     14545    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11366    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    12406    
unix  3      [ ]         STREAM     CONNECTED     12779    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     12429    
unix  3      [ ]         STREAM     CONNECTED     12669    /run/user/1000/at-spi/bus_0
unix  3      [ ]         STREAM     CONNECTED     11734    
unix  3      [ ]         STREAM     CONNECTED     14406    /run/user/1000/bus
unix  2      [ ]         DGRAM                    12575    
unix  3      [ ]         STREAM     CONNECTED     10793    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11864    
unix  3      [ ]         STREAM     CONNECTED     14352    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     7566     /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     11724    
unix  3      [ ]         STREAM     CONNECTED     19133    
unix  3      [ ]         STREAM     CONNECTED     13392    /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     10865    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     9150     
unix  3      [ ]         STREAM     CONNECTED     6919     
unix  3      [ ]         STREAM     CONNECTED     11884    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     13353    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     14433    
unix  3      [ ]         STREAM     CONNECTED     11731    
unix  3      [ ]         STREAM     CONNECTED     9824     
unix  3      [ ]         STREAM     CONNECTED     8189     /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM      CONNECTED     3988     
unix  3      [ ]         STREAM     CONNECTED     12717    
unix  2      [ ACC ]     STREAM     LISTENING     10186    @/tmp/.ICE-unix/1190
unix  3      [ ]         STREAM     CONNECTED     7696     @26ab63e108bf76b8/bus/systemd-logind/system
unix  2      [ ACC ]     STREAM     LISTENING     11329    @/tmp/.X11-unix/X0
unix  3      [ ]         STREAM     CONNECTED     10938    @c3c23a862c7d54a3/bus/systemd/bus-system
unix  2      [ ]         STREAM                   11865    @printer-applet-lock-user-serg
unix  3      [ ]         STREAM     CONNECTED     7118     @37edc6b72b44db9f/bus/systemd/bus-api-system
unix  3      [ ]         STREAM     CONNECTED     11019    @47a13236810c8029/bus/systemd/bus-api-user
unix  3      [ ]         STREAM     CONNECTED     8511     @144f4c86fa092bc4/bus/systemd-timesyn/bus-api-timesync
unix  3      [ ]         STREAM     CONNECTED     6905     @b26b72918550dc22/bus/systemd-resolve/bus-api-resolve
```

Разберём частично вывод:

- **`tcp 0 0 _localdnsproxy:domain *:* LISTEN`** - **domain** - это порт **53** (стандартный порт для DNS). Имя `_localdnsproxy` и `_localdnsstub` - это специальные системные имена, которые резолвятся в локальный адрес (127.0.0.53). **LISTEN** - значит сервисы, которые ожидают входящих подключений.

- **`udp 0 0 0.0.0.0:56999 0.0.0.0:*`** - UDP работает по принципу "отправил и забыл", поэтому у него нет состояний вроде `LISTEN` или `ESTABLISHED`.Скорее всего, это временные порты, которые случайным образом выбрала какая-то программа для исходящего UDP-соединения (например, для игр, VoIP, DNS-запросов);

Попробуем посмотреть PID процессов активных соединений, при помощи команды: **netstat -p**

```bash
serg@serg-pc:~$ netstat -p
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
udp        0      0 serg-pc:bootpc          _gateway:bootps         ESTABLISHED -                   
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name     Path
unix  3      [ ]         STREAM     CONNECTED     12014    1226/dbus-daemon     /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     13464    1635/mate-xapp-stat  
unix  3      [ ]         STREAM     CONNECTED     9696     -                    
unix  3      [ ]         STREAM     CONNECTED     13733    1908/evolution-addr  
unix  3      [ ]         STREAM     CONNECTED     13677    -                    /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM      CONNECTED     12128    1844/obexd           
unix  3      [ ]         STREAM     CONNECTED     12408    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     11055    1844/obexd           
unix  3      [ ]         STREAM     CONNECTED     13463    1635/mate-xapp-stat  
unix  3      [ ]         STREAM     CONNECTED     11680    1214/pipewire        
unix  3      [ ]         STREAM     CONNECTED     11123    1226/dbus-daemon     /run/user/1000/bus
unix  3      [ ]         STREAM     CONNECTED     11074    1655/python3         
unix  2      [ ]         DGRAM                    13550    1592/goa-daemon      
unix  3      [ ]         STREAM     CONNECTED     12636    1545/at-spi2-regist  

```

Как видим, перед процессами появился PID (Process IDentifier) - уникальный порядковый номер процесса, по которому его, например, можно завершить, тем самым и сбросив его сетевое соединение.

Посмотрим статистику по портам при помощи команды: **sudo netstat -tunlp**

```bash
serg@serg-pc:~$ sudo netstat -tunlp
[sudo] password for serg:       
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      614/systemd-resolve 
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      968/cupsd           
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      614/systemd-resolve 
tcp6       0      0 ::1:631                 :::*                    LISTEN      968/cupsd           
udp        0      0 127.0.0.54:53           0.0.0.0:*                           614/systemd-resolve 
udp        0      0 127.0.0.53:53           0.0.0.0:*                           614/systemd-resolve 
udp        0      0 0.0.0.0:33712           0.0.0.0:*                           632/avahi-daemon: r 
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           632/avahi-daemon: r 
udp6       0      0 :::5353                 :::*                                632/avahi-daemon: r 
udp6       0      0 :::43068                :::*                                632/avahi-daemon: r 
```

В данной статистике отображается протокол и порты, а также статус LISTEN говорит о том, что порт в данный момент слушает - это означает, что приложение запущено и ожидает подключений к определённому порту.

Теперь выведем другую статистику, посмотрим не кто и куда подключен, а как именно работают сетевые протоколы и сколько ошибок в них происходит. Для этого введём команду: **netstat -s**

```bash
serg@serg-pc:~$ netstat -s
Ip:
    Forwarding: 2
    276 total packets received
    0 forwarded
    0 incoming packets discarded
    273 incoming packets delivered
    269 requests sent out
    20 outgoing packets dropped
    OutTransmits: 269
Icmp:
    40 ICMP messages received
    0 input ICMP message failed
    ICMP input histogram:
        destination unreachable: 40
    40 ICMP messages sent
    0 ICMP messages failed
    ICMP output histogram:
        destination unreachable: 40
IcmpMsg:
        InType3: 40
        OutType3: 40
Tcp:
    155 active connection openings
    0 passive connection openings
    146 failed connection attempts
    0 connection resets received
    0 connections established
    199 segments received
    202 segments sent out
    0 segments retransmitted
    0 bad segments received
    2 resets sent
Udp:
    140 packets received
    40 packets to unknown port received
    0 packet receive errors
    169 packets sent
    0 receive buffer errors
    0 send buffer errors
UdpLite:
TcpExt:
    4 TCP sockets finished time wait in fast timer
    2 delayed acks sent
    0 packet headers predicted
    8 acknowledgments not containing data payload received
    12 predicted acknowledgments
    IPReversePathFilter: 1
    TCPRcvCoalesce: 4
    TCPOrigDataSent: 21
    TCPDelivered: 30
IpExt:
    InMcastPkts: 52
    OutMcastPkts: 54
    InOctets: 40776
    OutOctets: 24956
    InMcastOctets: 6520
    OutMcastOctets: 6600
    InNoECTPkts: 276
MPTcpExt:

```

В данной статистике мы видим:

- **Ip** (Протокол IP): Статистика по IPv4 и IPv6;

- **Icmp** (Internet Control Message Protocol): Статистика по запросам и ответам (например, ping);

- **IcmpMsg** (Типы ICMP-сообщений): Детализация по типам ICMP-сообщений;

- **Tcp** (Transmission Control Protocol): Очень подробная статистика по TCP-соединениям (самая полезная часть);

- **Udp** (User Datagram Protocol): Статистика по UDP-датаграммам;

- **UdpLite** (если используется);

Если мы хотим получить данные только по конкретному порту, например, по порту 68, то можно ввести такую команду: **sudo netstat -tunp | grep :68**

```bash
serg@serg-pc:~$ sudo netstat -tunp | grep :68
udp        0      0 10.0.2.15:68            10.0.2.2:67             ESTABLISHED 755/NetworkManagert
```

Данный вывод говорит нам о том, что IP-адрес 10.0.2.15 и порт 68 узла клиента, с которым установлено соединение подключён к 10.0.2.2 к порту 67.

## traceroute

Утилита traceroute создана, чтобы показать путь, который пакеты данных проходят от вашего компьютера до целевого узла в сети, и измерить задержки на каждом участке этого пути. Эта утилита отлично подходит для того, чтобы найти конкретный участок сети, где происходят потеря пакетов или большие задержки. Также traceroute позволяет понять, где именно возникает проблема: у вашего провайдера, у одного из промежуточных провайдеров или на стороне целевого сервера.

Принцип работы traceroute основан на эксплуатации поля **TTL (Time To Live)** в заголовке IP-пакета. TTL - это некий счётчик прыжков. Его значение уменьшается на 1 каждый раз, когда пакет проходит через очередной маршрутизатор (роутер). Но когда TTL достигает 0, маршрутизатор, который его обработал, **отбрасывает пакет** и отправляет обратно отправителю специальное ICMP-сообщение: **"Time Exceeded"**, что означает "Время истекло".

Сначала traceroute отправляет towards цели пакет (UDP, ICMP или TCP, в зависимости от опций) с установленным **TTL = 1**, затем первый же маршрутизатор на пути уменьшает TTL на 1 (получается 0), отбрасывает пакет и отправляет обратно сообщение "Time Exceeded". После этого traceroute фиксирует адрес этого маршрутизатора и время между отправкой пакета и получением ответа. Далее traceroute отправляет следующий пакет с **TTL = 2**. Этот пакет проходит первый маршрутизатор (TTL уменьшается до 1), доходит до второго маршрутизатора. Тот уменьшает TTL до 0, отбрасывает пакет и отправляет обратно "Time Exceeded". Таким образом traceroute узнаёт адрес второго маршрутизатора. Процесс повторяется с TTL = 3, 4, 5 и так далее, пока пакет не достигнет конечной цели. В самом конце, когда пакет с конечным TTL доходит до целевого хоста, тот, вместо сообщения "Time Exceeded", отправляет сообщение **"Destination Unreachable"** (для UDP) или **"Echo Reply"** (для ICMP). Получив этот ответ,  утилита traceroute понимает, что маршрут построен, и завершает работу.

Посмотрим работу утилиты при помощи команды: **traceroute -n google.com**

```bash
serg@serg-pc:~$ traceroute -n google.com
traceroute to google.com (173.194.221.139), 30 hops max, 60 byte packets
 1  10.0.2.2  0.371 ms  0.340 ms  0.322 ms
 2  10.0.2.2  2.995 ms  2.973 ms  2.849 ms
```

Разберём данный вывод:

- Первая колонка показывает порядковый номер маршрутизатора на пути;

- Вторая колонка - это адрес маршрутизатора;

- Далее идут три колонки со временем прохождения (RTT) для трёх отправленных пакетов до этого маршрутизатора. Измеряется в миллисекундах (мс). Показывает задержку на этом участке;

Если выводе после порядкового номера нам попадутся звёздочки (* * *) - это означает, что на этот хоп не пришло ответа в течение таймаута. Причины этого, либо маршрутизатор настроен игнорировать такие запросы (частая практика для безопасности), либо пакеты были потеряны на этом участке, либо ответ идёт обратно слишком долго.

Утилита traceroute позволяет выбрать типы пакетов, если в команду добавить соответствующий ключ:

- **-I** - отправляет **ICMP** Echo-запросы, как утилита ping;

- **-T** - отправляет **TCP** SYN-пакеты (обычно на порт 80);

- **-U** - отправляет **UDP**-пакеты на порт 53 (DNS);

Также есть и ключи для ввода настроек утилиты:

- **-n** - позволяет не преобразовывать IP-адреса в имена, что соответственно ускоряет вывод;

- **-q <число>** - позволяет задавать количество пробных запросов на хоп (по умолчанию задано 3);

- **-m <число>** - позволяет задавать максимальное количество прыжков (макс. TTL). По умолчанию задано 30;

- **-w <секунды>** - позволяет задавать время ожидания ответа (таймаут);

- **-f <число>** - позволяет установить начальное значение TTL (например, начать с 5-го хопа);

- **-p <порт>** - позволяет указать целевой порт для UDP и TCP методов;

- **-N <число>** - позволяет задавать число запросов, чтобы отправлять несколько запросов параллельно, что значительно ускоряет работу;

- **-A** - позволяет определить AS (Autonomous System) для каждого хопа;

Попробуем собрать универсальную команду для обхода строгих firewall: **sudo traceroute -T -p 443 -n google.com**

```bash
serg@serg-pc:~$ sudo traceroute -T -p 443 -n google.com
[sudo] password for serg:       
traceroute to google.com (173.194.221.100), 30 hops max, 60 byte packets
 1  173.194.221.100  11.592 ms  13.488 ms  11.696 ms

```

В данной команде мы использовали TCP, который почти всегда разрешён, имитировали HTTPS-соединение, которое редко блокируется, и для ускорения работы команды указали, чтобы утилита не преобразовывала IP-адреса в имена.

## nslookup

Утилита **nslookup** (Name Server Lookup) - это сетевая утилита командной строки, предназначенная для отправки запроса на DNS-сервера с целью получения информации о доменных именах и IP-адресах.

Проще говоря, её основная задача - спрашивать у DNS-серверов: "Какой IP-адрес у этого сайта?" или наоборот "Какому сайту принадлежит этот IP-адрес?".

В добавок, данная утилита позволяет получить дополнительную информации о домене. Nslookup может узнать **MX-записи** (почтовые серверы домена), **NS-записи** (DNS-серверы, отвечающие за домен) или узнать **TXT-записи** (часто используются для проверок владения, SPF, DKIM).

Принцип работы этой утилиты очень простой: она формирует DNS-запрос определенного типа и отправляет его на указанный DNS-сервер, а затем получает и отображает ответ. То есть, утилита отправляет DNS-запрос типа **A** (запись адреса для IPv4) или **AAAA** (для IPv6) на DNS-сервер, указанный в настройках сетевого подключения вашего компьютера. Этот сервер обычно выдается вашим роутером или провайдером автоматически через DHCP. Далее DNS-сервер обрабатывает запрос. Если у него есть ответ в кэше, он возвращает его сразу. Если нет, он сам запрашивает информацию у других DNS-серверов, начиная с корневых, и затем возвращает ответ вам. В последнем этапе nslookup получает ответ от сервера и выводит его вам в удобочитаемом виде.

Утилита может работать в двух режимах:

- **Интерактивный режим:** Если просто ввести команду **nslookup** без параметров. Вы попадаете в подобие командной строки, где можно делать много запросов подряд и менять параметры (например, тип запроса);

- **Режим одной команды (Non-Interactive):** Если ввести команду **nslookup <имя>**, утилита выполнит один запрос и завершит работу;

Теперь попробуем узнать IP-адрес по доменному имени, введя команду: **nslookup github.com**

```bash
serg@serg-pc:~$ nslookup github.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
Name:	github.com
Address: 140.82.121.4
```

Из ответа видим, что IP адрес сервера сайта github.com - 140.82.121.4. Также в ответе есть два блока:

- **Server:** Показывает, какой DNS-сервер дал ответ (здесь это локальный кэширующий резолвер);

- **Non-authoritative answer:** Ответ был получен из кэша сервера, а не непосредственно с авторитативных DNS-серверов домена github.com`;

Попробуем и обратную процедуру - узнать доменное имя по IP-адресу, введя команду: **nslookup 140.82.121.4**

```bash
serg@serg-pc:~$ nslookup 140.82.121.4
4.121.82.140.in-addr.arpa	name = lb-140-82-121-4-fra.github.com.
```

Система DNS для обратных запросов использует специальный домен **in-addr.arpa**. А в поле **name** мы получили доменное имя от данного IP адреса.

Теперь попробуем узнать почтовые серверы домена (MX-записи) у Gmail, введя команду: **nslookup -type=MX gmail.com**

```bash
serg@serg-pc:~$ nslookup -type=MX gmail.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
gmail.com	mail exchanger = 20 alt2.gmail-smtp-in.l.google.com.
gmail.com	mail exchanger = 40 alt4.gmail-smtp-in.l.google.com.
gmail.com	mail exchanger = 10 alt1.gmail-smtp-in.l.google.com.
gmail.com	mail exchanger = 30 alt3.gmail-smtp-in.l.google.com.
gmail.com	mail exchanger = 5 gmail-smtp-in.l.google.com.
```

Обратим внимание на табличку в выводе после надписи "Non-authoritative answer". Она показывает все почтовые серверы для `gmail.com`. Каждая строка состоит из двух последних основных частей:

1. **Приоритет (Preference):** Число перед именем сервера (20, 40, 10, 30, 5).

2. **Имя почтового сервера:** Например, alt2.gmail-smtp-in.l.google.com.

Почтовые серверы пытаются использовать в первую очередь серверы с **наименьшим** числом приоритета. Если сервер с высшим приоритетом недоступен, они переходят к следующему по порядку. Это показывает высокую отказоустойчивость почтовой системы Google.

Попробуем также запросить DNS-серверы, ответственные за домен (NS-записи), введя команду: nslookup -type=NS google.com

```bash
serg@serg-pc:~$ nslookup -type=NS google.com
Server:		127.0.0.53
Address:	127.0.0.53#53

Non-authoritative answer:
google.com	nameserver = ns2.google.com.
google.com	nameserver = ns4.google.com.
google.com	nameserver = ns3.google.com.
google.com	nameserver = ns1.google.com.
```

У Google, как видим 4 NS сервера. NS сервер это специализированный сервер, который хранит **DNS-записи** для определенной зоны (обычно для одного или нескольких доменов) и отвечает на запросы о соответствии доменных имен IP-адресам (и наоборот).
