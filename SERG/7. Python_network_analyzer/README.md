# Net Analyzer — real-time network anomaly detector (Scapy)

**Важно:** этот проект предназначен только для обнаружения аномалий/атак.

## Что делает

Захватывает пакеты в реальном времени и по эвристикам пытается обнаружить:

- SYN flood (TCP);
- Port scanning (TCP/UDP);
- ARP spoofing / Gratuitous ARP DoS;
- DHCP starvation;
- DNS spoofing (много разных ответов);
- IP fragmentation attacks;
- Smurf (ICMP amplification);
- HTTP slow POST (slowloris-like POST);

## Установка

1. Создайте виртуальное окружение:
   
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

## Запуск

```bash
sudo python3 main.py -i <интерфейс>
# например
sudo python3 main.py -i eth0
```

## Настройка виртуальной лаборатории

Для тестирования проекта **обязательно используйте изолированную виртуальную среду**:

1. Создайте 2–3 виртуальные машины (например, в VirtualBox или VMware):
   
   - VM-Analyzer (Ubuntu/Linux) — запускает анализатор (`main.py`);
   - VM-Traffic (Ubuntu/Linux) — проигрывает PCAP через `tcpreplay`;
   - VM-Target (опционально) — «жертва», чтобы было видно распределение трафика;

2. В настройках сети выберите один из режимов:
   
   - **Internal Network** (VirtualBox: `intnet`);
   - или **Host-Only Adapter**;
   
   ⚠️ Важно: **не используйте NAT или Bridged Adapter** — это может вывести трафик наружу в вашу реальную сеть.

3. Убедитесь, что машины «видят» друг друга по IP внутри этой сети:
   
   ```bash
   ip a        # смотрим IP интерфейсов
   ping <IP другой VM>
   ```

## Генерация PCAP-файлов

Сначала создаём PCAP с характерным трафиком:

```bash
# SYN flood
python3 pcap_generator.py --synflood syn.pcap --count 2000

# ARP spoof
python3 pcap_generator.py --arp_spoof arp_spoof.pcap

# Gratuitous ARP
python3 pcap_generator.py --garp garp.pcap

# DHCP Starvation
python3 pcap_generator.py --dhcp_starvation dhcp_starve.pcap

# Portscan
python3 pcap_generator.py --portscan portscan.pcap --count 1000

# ICMP Smurf
python3 pcap_generator.py --icmp_smurf icmp_smurf.pcap --count 500

# IP Fragmentation
python3 pcap_generator.py --fragments fragments.pcap

# DNS spoof-like
python3 pcap_generator.py --dns_spoof dns_spoof.pcap --count 200
```

## Проигрывание PCAP в VM

На машине VM-Traffic установите `tcpreplay`:

```bash
sudo apt update
sudo apt install -y tcpreplay
```

Примеры команд:

```bash
# Проиграть файл syn.pcap по интерфейсу eth0
sudo tcpreplay --intf1=eth0 syn.pcap

# Проиграть с ограничением скорости
sudo tcpreplay --intf1=eth0 --mbps=10 syn.pcap

# Проиграть несколько раз подряд
sudo tcpreplay --intf1=eth0 --loop=5 portscan.pcap
```

## Список PCAP и ожидаемые алерты

| PCAP-файл          | Описание атаки/аномалии               | Ожидаемый детектор             |
| ------------------ | ------------------------------------- | ------------------------------ |
| `syn.pcap`         | Множество TCP SYN → SYN Flood         | `SynFloodDetector`             |
| `arp_spoof.pcap`   | ARP is-at с разными MAC для одного IP | `ArpDetector` (ARP spoofing)   |
| `garp.pcap`        | Много Gratuitous ARP                  | `ArpDetector` (Gratuitous ARP) |
| `dhcp_starve.pcap` | Множество DHCPDISCOVER от разных MAC  | `DhcpDetector`                 |
| `portscan.pcap`    | Подключение к множеству портов        | `PortScanDetector`             |
| `icmp_smurf.pcap`  | ICMP Echo на широковещательный адрес  | `IcmpDetector` (Smurf)         |
| `fragments.pcap`   | Большое число IP фрагментов           | `FragmentationDetector`        |
| `dns_spoof.pcap`   | Несколько разных DNS ответов          | `DnsSpoofDetector`             |

##### 📄Логи отчёта предоставлены [в файле](./logs.txt)
