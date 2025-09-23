# network_analyzer_user_interface.py
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from collections import defaultdict, deque
import time
import threading
import platform

class NetworkAnalyzer:
    def __init__(self):
        # Статистика для обнаружения аномалий
        self.syn_count = defaultdict(lambda: deque(maxlen=100))
        self.arp_table = defaultdict(set)
        self.dhcp_requests = deque(maxlen=1000)
        self.port_scan_attempts = defaultdict(lambda: defaultdict(int))
        self.http_requests = deque(maxlen=100)
        self.fragmented_packets = deque(maxlen=100)
        self.icmp_packets = deque(maxlen=1000)
        
        # Пороги для обнаружения аномалий
        self.thresholds = {
            'syn_flood': 20,      # SYN пакетов в секунду
            'port_scan': 15,      # портов за короткое время
            'dhcp_starvation': 30, # DHCP запросов в секунду
            'http_slow_dos': 5,   # медленных POST запросов
            'ip_fragmentation': 50, # фрагментированных пакетов
            'smurf_attack': 50,   # ICMP пакетов в секунду
        }
        
        self.running = False
        self.packet_count = 0
        
    def get_available_interfaces(self):
        """Получить список доступных интерфейсов"""
        print("🔍 Searching for available interfaces...")
        interfaces = []
        
        try:
            # Используем scapy для получения интерфейсов
            iface_list = get_windows_if_list()
            for iface in iface_list:
                interfaces.append({
                    'name': iface['name'],
                    'description': iface.get('description', 'No description'),
                    'ips': iface.get('ips', [])
                })
                print(f"   Found: {iface['name']} - {iface.get('description', '')}")
        except Exception as e:
            print(f"   Warning: Could not get interfaces list: {e}")
            
        return interfaces
    
    def display_interfaces_menu(self):
        """Показать меню выбора интерфейса"""
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print("❌ No network interfaces found!")
            print("💡 Please check if Npcap is installed and try running as Administrator")
            return None
        
        print("\n📋 Available network interfaces:")
        print("-" * 50)
        
        for i, iface in enumerate(interfaces):
            ip_info = ""
            if iface['ips']:
                ip_info = f" | IPs: {', '.join(iface['ips'][:2])}"  # Показываем первые 2 IP
            print(f"{i+1}. {iface['name']} - {iface['description']}{ip_info}")
        
        print("-" * 50)
        
        while True:
            try:
                choice = input("\n🎯 Select interface by number or type interface name: ").strip()
                
                if choice.isdigit():
                    # Выбор по номеру
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(interfaces):
                        selected_iface = interfaces[choice_num - 1]['name']
                        print(f"✅ Selected interface: {selected_iface}")
                        return selected_iface
                    else:
                        print(f"❌ Please enter a number between 1 and {len(interfaces)}")
                
                else:
                    # Прямой ввод имени интерфейса
                    if choice:
                        # Проверяем существует ли интерфейс
                        iface_names = [iface['name'] for iface in interfaces]
                        if choice in iface_names:
                            print(f"✅ Selected interface: {choice}")
                            return choice
                        else:
                            print(f"❌ Interface '{choice}' not found in available interfaces.")
                            print("💡 Available interfaces:", ", ".join(iface_names))
                            continue_option = input("💡 Do you want to try anyway? (y/n): ").strip().lower()
                            if continue_option == 'y':
                                print(f"⚠️ Trying interface: {choice}")
                                return choice
                            else:
                                continue
                
            except KeyboardInterrupt:
                print("\n⏹️ Selection cancelled.")
                return None
            except Exception as e:
                print(f"❌ Error: {e}")
                continue
    
    def start_monitoring(self, interface_name=None):
        """Запуск мониторинга сети"""
        if not interface_name:
            interface_name = self.display_interfaces_menu()
            if not interface_name:
                return False
            
        print(f"🎯 Using interface: {interface_name}")
        self.running = True
        
        # Запускаем очистку старых данных
        cleaner_thread = threading.Thread(target=self._clean_old_data)
        cleaner_thread.daemon = True
        cleaner_thread.start()
        
        # Запускаем отображение статистики
        stats_thread = threading.Thread(target=self._show_stats)
        stats_thread.daemon = True
        stats_thread.start()
        
        try:
            print("🚀 Starting packet capture...")
            print("📡 Monitoring network traffic... Press Ctrl+C to stop")
            
            # Используем L3socket для избежания проблем с layer 2
            conf.L3socket = conf.L3socket6
            
            # Захватываем пакеты
            sniff(prn=self._packet_handler, iface=interface_name, store=0)
            
        except Exception as e:
            print(f"❌ Capture error: {e}")
            print("💡 Possible solutions:")
            print("   1. Run the script as Administrator")
            print("   2. Check if Npcap is installed")
            print("   3. Verify the interface name")
            return False
            
        return True
    
    def _clean_old_data(self):
        """Очистка старых данных"""
        while self.running:
            time.sleep(60)
            current_time = time.time()
            
            for src_ip in list(self.port_scan_attempts.keys()):
                for port in list(self.port_scan_attempts[src_ip].keys()):
                    if current_time - self.port_scan_attempts[src_ip][port] > 300:
                        del self.port_scan_attempts[src_ip][port]
    
    def _show_stats(self):
        """Показ статистики"""
        while self.running:
            time.sleep(10)
            self.print_stats()
    
    def _packet_handler(self, packet):
        """Обработчик каждого пакета"""
        self.packet_count += 1
        
        try:
            # Анализ IP пакетов
            if packet.haslayer(IP):
                self._analyze_ip(packet)
            
            # Анализ TCP
            if packet.haslayer(TCP):
                self._analyze_tcp(packet)
            
            # Анализ UDP
            if packet.haslayer(UDP):
                self._analyze_udp(packet)
            
            # Анализ ICMP
            if packet.haslayer(ICMP):
                self._analyze_icmp(packet)
            
            # Анализ ARP
            if packet.haslayer(ARP):
                self._analyze_arp(packet)
                
        except Exception as e:
            if self.packet_count % 100 == 0:
                print(f"⚠️ Packet processing error: {e}")
    
    def _analyze_ip(self, packet):
        """Анализ IP пакетов"""
        ip = packet[IP]
        current_time = time.time()
        
        # Обнаружение атаки фрагментации IP
        if hasattr(ip, 'flags') and ip.flags == 1:  # MF флаг
            self.fragmented_packets.append(current_time)
            self._check_ip_fragmentation_attack()
    
    def _analyze_tcp(self, packet):
        """Анализ TCP пакетов"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP]
            tcp = packet[TCP]
            current_time = time.time()
            src_ip = ip.src
            
            # Обнаружение SYN Flood
            if hasattr(tcp, 'flags') and tcp.flags == 0x02:  # SYN пакет
                self.syn_count[src_ip].append(current_time)
                self._check_syn_flood(src_ip)
            
            # Обнаружение порт-сканирования
            if hasattr(tcp, 'flags') and tcp.flags in [0x02, 0x01, 0x20, 0x08]:  # SYN, FIN, URG, PSH
                self.port_scan_attempts[src_ip][tcp.dport] = current_time
                self._check_port_scan(src_ip)
            
            # Обнаружение HTTP трафика
            if tcp.dport == 80 or tcp.sport == 80:
                if packet.haslayer(Raw):
                    try:
                        raw_data = str(packet[Raw].load)
                        if "POST" in raw_data or "GET" in raw_data:
                            self.http_requests.append((current_time, len(raw_data)))
                            self._check_http_slow_dos()
                    except:
                        pass
    
    def _analyze_udp(self, packet):
        """Анализ UDP пакетов"""
        if packet.haslayer(IP) and packet.haslayer(UDP):
            ip = packet[IP]
            udp = packet[UDP]
            src_ip = ip.src
            
            # Обнаружение порт-сканирования UDP
            self.port_scan_attempts[src_ip][udp.dport] = time.time()
            self._check_port_scan(src_ip)
            
            # Обнаружение DHCP Starvation
            if udp.sport == 68 and udp.dport == 67:  # DHCP запрос
                self.dhcp_requests.append(time.time())
                self._check_dhcp_starvation()
    
    def _analyze_icmp(self, packet):
        """Анализ ICMP пакетов"""
        if packet.haslayer(IP):
            current_time = time.time()
            self.icmp_packets.append(current_time)
            self._check_smurf_attack()
    
    def _analyze_arp(self, packet):
        """Анализ ARP пакетов"""
        arp = packet[ARP]
        
        # Обнаружение ARP Spoofing
        if arp.op == 2:  # ARP Reply
            self._check_arp_spoofing(arp)
        
        # Обнаружение Gratuitous ARP
        if arp.op == 2 and arp.psrc == arp.pdst:
            self._check_gratuitous_arp(arp)
    
    def _check_syn_flood(self, src_ip):
        """Проверка на SYN Flood атаку"""
        window = 1
        current_time = time.time()
        
        syn_in_window = sum(1 for timestamp in self.syn_count[src_ip] 
                           if current_time - timestamp < window)
        
        if syn_in_window > self.thresholds['syn_flood']:
            print(f"🚨 SYN Flood detected from {src_ip}: {syn_in_window} SYN packets in {window} second")
    
    def _check_port_scan(self, src_ip):
        """Проверка на порт-сканирование"""
        current_time = time.time()
        window = 10
        
        recent_ports = [port for port, timestamp in self.port_scan_attempts[src_ip].items()
                       if current_time - timestamp < window]
        
        if len(recent_ports) > self.thresholds['port_scan']:
            print(f"🚨 Port Scan detected from {src_ip}: {len(recent_ports)} ports scanned in {window} seconds")
    
    def _check_dhcp_starvation(self):
        """Проверка на DHCP Starvation атаку"""
        window = 1
        current_time = time.time()
        
        dhcp_in_window = sum(1 for timestamp in self.dhcp_requests 
                            if current_time - timestamp < window)
        
        if dhcp_in_window > self.thresholds['dhcp_starvation']:
            print(f"🚨 DHCP Starvation detected: {dhcp_in_window} DHCP requests in {window} second")
    
    def _check_http_slow_dos(self):
        """Проверка на медленный HTTP POST DoS"""
        window = 10
        current_time = time.time()
        
        slow_requests = sum(1 for timestamp, size in self.http_requests 
                           if current_time - timestamp < window and size < 100)
        
        if slow_requests > self.thresholds['http_slow_dos']:
            print(f"🚨 HTTP Slow POST DoS detected: {slow_requests} slow requests in {window} seconds")
    
    def _check_ip_fragmentation_attack(self):
        """Проверка на атаку фрагментации IP"""
        window = 1
        current_time = time.time()
        
        fragmented_in_window = sum(1 for timestamp in self.fragmented_packets 
                                  if current_time - timestamp < window)
        
        if fragmented_in_window > self.thresholds['ip_fragmentation']:
            print(f"🚨 IP Fragmentation Attack detected: {fragmented_in_window} fragmented packets in {window} second")
    
    def _check_smurf_attack(self):
        """Проверка на Smurf атаку"""
        window = 1
        current_time = time.time()
        
        icmp_in_window = sum(1 for timestamp in self.icmp_packets 
                            if current_time - timestamp < window)
        
        if icmp_in_window > self.thresholds['smurf_attack']:
            print(f"🚨 Smurf Attack detected: {icmp_in_window} ICMP packets in {window} second")
    
    def _check_arp_spoofing(self, arp_packet):
        """Проверка на ARP Spoofing"""
        ip = arp_packet.psrc
        mac = arp_packet.hwsrc
        
        if ip in self.arp_table:
            if mac not in self.arp_table[ip]:
                print(f"🚨 ARP Spoofing detected: IP {ip} was {self.arp_table[ip]}, now claiming to be {mac}")
        else:
            self.arp_table[ip].add(mac)
    
    def _check_gratuitous_arp(self, arp_packet):
        """Проверка на Gratuitous ARP DoS"""
        print(f"🚨 Gratuitous ARP detected from {arp_packet.hwsrc} for IP {arp_packet.psrc}")
    
    def print_stats(self):
        """Вывод текущей статистики"""
        print(f"\n📊 Statistics - Packets processed: {self.packet_count}")
        print(f"   Active hosts: {len(self.syn_count)}")
        print(f"   Port scan attempts: {sum(len(ports) for ports in self.port_scan_attempts.values())}")
        print("---")
    
    def stop_monitoring(self):
        """Остановка мониторинга"""
        self.running = False
        print("\n🛑 Monitoring stopped")

def test_analyzer():
    """Тестирование анализатора с помощью имитации трафика"""
    print("🧪 Starting analyzer test in background...")
    
    # Имитируем некоторый трафик
    from scapy.all import send, IP, TCP
    import threading
    
    def send_test_packets():
        """Отправка тестовых пакетов"""
        time.sleep(3)  # Даем время анализатору запуститься
        
        print("📤 Sending test packets...")
        
        # Отправляем несколько SYN пакетов для тестирования
        for i in range(15):
            src_ip = f"192.168.1.{i+100}"
            packet = IP(src=src_ip, dst="8.8.8.8")/TCP(sport=1234+i, dport=80, flags="S")
            send(packet, verbose=0)
            time.sleep(0.02)
        
        print("✅ Test packets sent")
    
    # Запускаем отправку в отдельном потоке
    test_thread = threading.Thread(target=send_test_packets)
    test_thread.daemon = True
    test_thread.start()

def main():
    """Основная функция программы"""
    print("=== 🛡️ Network Security Analyzer ===")
    print("🔧 Version with user interface selection")
    print("💡 Please run as Administrator for best results")
    print("-" * 50)
    
    # Создаем анализатор
    analyzer = NetworkAnalyzer()
    
    # Показываем информацию о системе
    print(f"🏷️  OS: {platform.system()} {platform.release()}")
    print(f"🐍 Python: {platform.python_version()}")
    print("-" * 50)
    
    # Запускаем тест в фоне
    test_analyzer()
    
    try:
        # Запускаем мониторинг с выбором интерфейса
        analyzer.start_monitoring()
    except KeyboardInterrupt:
        print("\n⏹️ Program interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        analyzer.stop_monitoring()
        print("👋 Thank you for using Network Security Analyzer!")

if __name__ == "__main__":
    main()