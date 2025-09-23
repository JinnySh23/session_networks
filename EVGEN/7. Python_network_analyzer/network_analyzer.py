# network_analyzer_final.py
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from collections import defaultdict, deque
import time
import threading
import platform
import subprocess
import re

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
        """Получить список доступных интерфейсов с помощью разных методов"""
        print("🔍 Searching for available interfaces...")
        interfaces = []
        
        # Метод 1: Используем scapy.config.conf.ifaces
        try:
            if hasattr(conf, 'ifaces'):
                for iface_name, iface_obj in conf.ifaces.items():
                    interfaces.append({
                        'name': iface_name,
                        'description': str(iface_obj),
                        'ips': []
                    })
                print("✅ Found interfaces via scapy.conf.ifaces")
        except Exception as e:
            print(f"   Scapy conf.ifaces error: {e}")
        
        # Метод 2: Используем Windows команды
        windows_interfaces = self._get_windows_interfaces()
        for iface in windows_interfaces:
            if iface not in [i['name'] for i in interfaces]:
                interfaces.append({
                    'name': iface,
                    'description': 'Windows network interface',
                    'ips': []
                })
        
        # Метод 3: Common интерфейсы Windows
        common_interfaces = [
            "Ethernet", "Ethernet 7", "Wi-Fi", "Беспроводная сеть", 
            "Local Area Connection", "Wireless Network Connection",
            "Ethernet 2", "Ethernet 3", "Ethernet 4", "Ethernet 5", "Ethernet 6"
        ]
        
        for iface in common_interfaces:
            if iface not in [i['name'] for i in interfaces]:
                interfaces.append({
                    'name': iface,
                    'description': 'Common Windows interface',
                    'ips': []
                })
        
        # Убираем дубликаты
        unique_interfaces = []
        seen_names = set()
        for iface in interfaces:
            if iface['name'] not in seen_names:
                unique_interfaces.append(iface)
                seen_names.add(iface['name'])
        
        # Выводим найденные интерфейсы
        for iface in unique_interfaces:
            print(f"   📡 {iface['name']} - {iface['description']}")
        
        return unique_interfaces
    
    def _get_windows_interfaces(self):
        """Получить интерфейсы через Windows команды"""
        interfaces = []
        
        try:
            # Команда для получения интерфейсов
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Connected' in line or 'Disconnected' in line:
                        parts = line.split()
                        if len(parts) > 3:
                            # Ищем имя интерфейса (обычно в конце строки)
                            iface_name = ' '.join(parts[3:]).strip()
                            if iface_name and iface_name not in interfaces:
                                interfaces.append(iface_name)
        except:
            pass
        
        return interfaces
    
    def test_interface(self, interface_name):
        """Протестировать интерфейс на возможность захвата пакетов"""
        print(f"🧪 Testing interface: {interface_name}")
        
        try:
            # Пробуем создать сокет для интерфейса
            socket = conf.L3socket(iface=interface_name)
            socket.close()
            return True
        except:
            pass
        
        try:
            # Пробуем альтернативный метод
            socket = conf.L3socket6(iface=interface_name)
            socket.close()
            return True
        except:
            pass
        
        return False
    
    def display_interfaces_menu(self):
        """Показать меню выбора интерфейса"""
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print("❌ No network interfaces found automatically.")
            print("💡 Trying manual interface selection...")
            return self._manual_interface_selection()
        
        print("\n📋 Available network interfaces:")
        print("=" * 60)
        
        for i, iface in enumerate(interfaces):
            status = "✅" if self.test_interface(iface['name']) else "❌"
            print(f"{i+1}. {status} {iface['name']} - {iface['description']}")
        
        print("=" * 60)
        print("💡 Interfaces marked with ✅ are likely to work")
        print("💡 Interfaces marked with ❌ may not work properly")
        
        while True:
            try:
                choice = input("\n🎯 Select interface by number, type interface name, or 'scan' to rescan: ").strip()
                
                if choice.lower() == 'scan':
                    return self.display_interfaces_menu()
                
                if choice.isdigit():
                    # Выбор по номеру
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(interfaces):
                        selected_iface = interfaces[choice_num - 1]['name']
                        if self.test_interface(selected_iface):
                            print(f"✅ Selected interface: {selected_iface}")
                            return selected_iface
                        else:
                            print(f"⚠️ Interface {selected_iface} may not work properly.")
                            continue_option = input("💡 Do you want to try anyway? (y/n): ").strip().lower()
                            if continue_option == 'y':
                                return selected_iface
                    else:
                        print(f"❌ Please enter a number between 1 and {len(interfaces)}")
                
                else:
                    # Прямой ввод имени интерфейса
                    if choice:
                        # Проверяем существует ли интерфейс в списке
                        iface_names = [iface['name'] for iface in interfaces]
                        if choice in iface_names:
                            if self.test_interface(choice):
                                print(f"✅ Selected interface: {choice}")
                                return choice
                            else:
                                print(f"⚠️ Interface {choice} may not work properly.")
                                continue_option = input("💡 Do you want to try anyway? (y/n): ").strip().lower()
                                if continue_option == 'y':
                                    return choice
                        else:
                            print(f"❌ Interface '{choice}' not found in available interfaces.")
                            print("💡 Available interfaces:", ", ".join(iface_names))
                            continue_option = input("💡 Do you want to try anyway? (y/n): ").strip().lower()
                            if continue_option == 'y':
                                print(f"⚠️ Trying interface: {choice}")
                                return choice
                
            except KeyboardInterrupt:
                print("\n⏹️ Selection cancelled.")
                return None
            except Exception as e:
                print(f"❌ Error: {e}")
                continue
    
    def _manual_interface_selection(self):
        """Ручной выбор интерфейса"""
        print("\n🔧 Manual interface selection")
        print("💡 Common Windows interfaces: Ethernet, Wi-Fi, Ethernet 7, etc.")
        
        common_interfaces = [
            "Ethernet", "Ethernet 7", "Wi-Fi", "Беспроводная сеть",
            "Local Area Connection", "Wireless Network Connection"
        ]
        
        print("💡 Try these common names:")
        for i, iface in enumerate(common_interfaces, 1):
            print(f"   {i}. {iface}")
        
        while True:
            try:
                iface_name = input("\n🎯 Enter interface name (or 'quit' to exit): ").strip()
                
                if iface_name.lower() == 'quit':
                    return None
                
                if iface_name:
                    print(f"🧪 Testing interface: {iface_name}")
                    if self.test_interface(iface_name):
                        print(f"✅ Interface {iface_name} seems to work!")
                        return iface_name
                    else:
                        print(f"⚠️ Interface {iface_name} may not work properly.")
                        continue_option = input("💡 Try anyway? (y/n): ").strip().lower()
                        if continue_option == 'y':
                            return iface_name
                
            except KeyboardInterrupt:
                return None
            except Exception as e:
                print(f"❌ Error: {e}")
                continue
    
    def start_monitoring(self, interface_name=None):
        """Запуск мониторинга сети"""
        if not interface_name:
            interface_name = self.display_interfaces_menu()
            if not interface_name:
                print("❌ No interface selected. Exiting.")
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
        
        # Запускаем тестовые пакеты
        self._start_test_traffic()
        
        try:
            print("🚀 Starting packet capture...")
            print("📡 Monitoring network traffic... Press Ctrl+C to stop\n")
            
            # Пробуем разные методы захвата
            try:
                # Метод 1: Обычный sniff
                sniff(prn=self._packet_handler, iface=interface_name, store=0, timeout=0.1)
            except:
                try:
                    # Метод 2: С L3socket
                    conf.L3socket = conf.L3socket6
                    sniff(prn=self._packet_handler, iface=interface_name, store=0, timeout=0.1)
                except:
                    # Метод 3: Без указания интерфейса
                    print("⚠️ Trying without specific interface...")
                    sniff(prn=self._packet_handler, store=0, timeout=0.1)
            
        except Exception as e:
            print(f"❌ Capture error: {e}")
            print("💡 Possible solutions:")
            print("   1. Make sure Npcap is installed: https://npcap.com/#download")
            print("   2. Try running as Administrator")
            print("   3. Try a different interface name")
            return False
            
        return True
    
    def _start_test_traffic(self):
        """Запуск тестового трафика для демонстрации"""
        def send_test_packets():
            time.sleep(2)
            print("🧪 Sending test packets for demonstration...")
            
            try:
                # Отправляем несколько тестовых пакетов
                for i in range(5):
                    packet = IP(dst="8.8.8.8")/TCP(dport=80, flags="S")
                    send(packet, verbose=0)
                    time.sleep(0.5)
                print("✅ Test packets sent\n")
            except:
                print("⚠️ Could not send test packets\n")
        
        test_thread = threading.Thread(target=send_test_packets)
        test_thread.daemon = True
        test_thread.start()
    
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
            time.sleep(15)
            if self.packet_count > 0:
                self.print_stats()
    
    def _packet_handler(self, packet):
        """Обработчик каждого пакета"""
        self.packet_count += 1
        
        # Показываем прогресс каждые 100 пакетов
        if self.packet_count % 100 == 0:
            print(f"📦 Processed {self.packet_count} packets...")
        
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
            if self.packet_count % 500 == 0:
                print(f"⚠️ Packet processing error: {e}")
    
    # Остальные методы анализа остаются без изменений
    def _analyze_ip(self, packet):
        """Анализ IP пакетов"""
        ip = packet[IP]
        current_time = time.time()
        
        if hasattr(ip, 'flags') and ip.flags == 1:
            self.fragmented_packets.append(current_time)
            self._check_ip_fragmentation_attack()
    
    def _analyze_tcp(self, packet):
        """Анализ TCP пакетов"""
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip = packet[IP]
            tcp = packet[TCP]
            current_time = time.time()
            src_ip = ip.src
            
            if hasattr(tcp, 'flags') and tcp.flags == 0x02:
                self.syn_count[src_ip].append(current_time)
                self._check_syn_flood(src_ip)
            
            if hasattr(tcp, 'flags') and tcp.flags in [0x02, 0x01, 0x20, 0x08]:
                self.port_scan_attempts[src_ip][tcp.dport] = current_time
                self._check_port_scan(src_ip)
            
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
            
            self.port_scan_attempts[src_ip][udp.dport] = time.time()
            self._check_port_scan(src_ip)
            
            if udp.sport == 68 and udp.dport == 67:
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
        
        if arp.op == 2:
            self._check_arp_spoofing(arp)
        
        if arp.op == 2 and arp.psrc == arp.pdst:
            self._check_gratuitous_arp(arp)
    
    def _check_syn_flood(self, src_ip):
        window = 1
        current_time = time.time()
        syn_in_window = sum(1 for timestamp in self.syn_count[src_ip] 
                           if current_time - timestamp < window)
        if syn_in_window > self.thresholds['syn_flood']:
            print(f"🚨 SYN Flood detected from {src_ip}: {syn_in_window} SYN packets in {window} second")
    
    def _check_port_scan(self, src_ip):
        current_time = time.time()
        window = 10
        recent_ports = [port for port, timestamp in self.port_scan_attempts[src_ip].items()
                       if current_time - timestamp < window]
        if len(recent_ports) > self.thresholds['port_scan']:
            print(f"🚨 Port Scan detected from {src_ip}: {len(recent_ports)} ports scanned in {window} seconds")
    
    def _check_dhcp_starvation(self):
        window = 1
        current_time = time.time()
        dhcp_in_window = sum(1 for timestamp in self.dhcp_requests 
                            if current_time - timestamp < window)
        if dhcp_in_window > self.thresholds['dhcp_starvation']:
            print(f"🚨 DHCP Starvation detected: {dhcp_in_window} DHCP requests in {window} second")
    
    def _check_http_slow_dos(self):
        window = 10
        current_time = time.time()
        slow_requests = sum(1 for timestamp, size in self.http_requests 
                           if current_time - timestamp < window and size < 100)
        if slow_requests > self.thresholds['http_slow_dos']:
            print(f"🚨 HTTP Slow POST DoS detected: {slow_requests} slow requests in {window} seconds")
    
    def _check_ip_fragmentation_attack(self):
        window = 1
        current_time = time.time()
        fragmented_in_window = sum(1 for timestamp in self.fragmented_packets 
                                  if current_time - timestamp < window)
        if fragmented_in_window > self.thresholds['ip_fragmentation']:
            print(f"🚨 IP Fragmentation Attack detected: {fragmented_in_window} fragmented packets in {window} second")
    
    def _check_smurf_attack(self):
        window = 1
        current_time = time.time()
        icmp_in_window = sum(1 for timestamp in self.icmp_packets 
                            if current_time - timestamp < window)
        if icmp_in_window > self.thresholds['smurf_attack']:
            print(f"🚨 Smurf Attack detected: {icmp_in_window} ICMP packets in {window} second")
    
    def _check_arp_spoofing(self, arp_packet):
        ip = arp_packet.psrc
        mac = arp_packet.hwsrc
        if ip in self.arp_table:
            if mac not in self.arp_table[ip]:
                print(f"🚨 ARP Spoofing detected: IP {ip} was {self.arp_table[ip]}, now claiming to be {mac}")
        else:
            self.arp_table[ip].add(mac)
    
    def _check_gratuitous_arp(self, arp_packet):
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

def main():
    """Основная функция программы"""
    print("=== 🛡️ Network Security Analyzer ===")
    print("🔧 Final version with improved interface detection")
    print("💡 Please run as Administrator for best results")
    print("-" * 60)
    
    # Проверяем права администратора
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️ Warning: Not running as Administrator!")
            print("💡 Some features may not work properly")
    except:
        pass
    
    # Создаем анализатор
    analyzer = NetworkAnalyzer()
    
    try:
        # Запускаем мониторинг
        if analyzer.start_monitoring():
            print("✅ Monitoring started successfully!")
        else:
            print("❌ Failed to start monitoring")
    except KeyboardInterrupt:
        print("\n⏹️ Program interrupted by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
    finally:
        analyzer.stop_monitoring()
        print("👋 Thank you for using Network Security Analyzer!")

if __name__ == "__main__":
    main()