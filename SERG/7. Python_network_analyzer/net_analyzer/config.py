# config.py
# Пороговые значения и параметры
WINDOW_SECONDS = 20  # окно в секундах для большинства детекторов

# SYN flood
SYN_THRESHOLD = 200           # число SYN в окне, сигнал тревоги
SYN_SRC_UNIQUE_THRESHOLD = 50 # уникальных источников

# Portscan
PORTSCAN_PORTS_THRESHOLD = 100  # число портов, к которым пытались подключиться в окне
PORTSCAN_UNIQUE_DST_THRESHOLD = 5

# ARP
ARP_CONFLICT_THRESHOLD = 3     # сколько раз пришли разные MAC для одного IP в окне
GARP_THRESHOLD = 10            # сколько gratuitous ARP за окно

# DHCP
DHCP_REQUESTS_THRESHOLD = 200  # discover/request messages in window
DHCP_UNIQUE_MAC_THRESHOLD = 100

# DNS spoofing
DNS_MULTIPLE_ANSWERS_THRESHOLD = 5

# IP fragmentation
FRAG_THRESHOLD = 300

# ICMP (Smurf)
ICMP_REPLY_THRESHOLD = 300

# HTTP slow POST heuristics
HTTP_SLOW_CONN_THRESHOLD = 50  # concurrent suspicious POSTs
HTTP_SLOW_DURATION = 10        # seconds of low throughput to consider "slow"

# Logging
ALERT_COOLDOWN_SECONDS = 10    # не спамить одно и то же предупреждение чаще чем
