import heapq
from typing import Dict, List, Optional, Tuple, Any
from packet import Packet, PacketType

class Router:
    def __init__(self, name: str):
        self.name = name
        self.interfaces: Dict[str, Dict] = {}
        self.connections: Dict[str, Tuple['Router', str, int]] = {}
        self.routing_table: Dict[str, Dict] = {}
        self.link_state_db: Dict[str, Dict[str, int]] = {}
        self.seq_num = 0
        
    def add_interface(self, interface: str, ip: str, mask: str = "255.255.255.0", metric: int = 1):
        """Добавляет интерфейс маршрутизатору"""
        self.interfaces[interface] = {"ip": ip, "mask": mask, "metric": metric}
        network = self.calculate_network(ip, mask)
        self.routing_table[network] = {
            "next_hop": "directly connected",
            "interface": interface,
            "metric": 0
        }
    
    def calculate_network(self, ip: str, mask: str) -> str:
        """Вычисляет сеть по IP и маске"""
        ip_parts = list(map(int, ip.split('.')))
        mask_parts = list(map(int, mask.split('.')))
        network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return '.'.join(map(str, network_parts))
    
    def connect(self, other: 'Router', interface1: str, interface2: str, metric1: int = 1, metric2: int = 1):
        """Устанавливает соединение между двумя маршрутизаторами"""
        self.connections[other.name] = (other, interface1, metric1)
        other.connections[self.name] = (self, interface2, metric2)
        print(f"Connected {self.name} ({interface1}) to {other.name} ({interface2})")
    
    def update_link_state(self):
        """Обновляет и рассылает информацию о состоянии каналов"""
        self.seq_num += 1
        self.link_state_db[self.name] = {}
        
        for neighbor, (router, interface, metric) in self.connections.items():
            self.link_state_db[self.name][neighbor] = metric
        
        for neighbor, (router, interface, metric) in self.connections.items():
            packet = Packet(
                source=self.name,
                destination=neighbor,
                payload={
                    "router_id": self.name,
                    "seq_num": self.seq_num,
                    "neighbors": self.link_state_db[self.name]
                },
                type=PacketType.LS_ANNOUNCEMENT
            )
            self.forward_packet(packet, interface)
    
    def receive_lsa(self, lsa_data: Dict, source: str):
        """Обрабатывает полученное LSA"""
        router_id = lsa_data["router_id"]
        seq_num = lsa_data["seq_num"]
        
        if (router_id not in self.link_state_db or 
            seq_num > self.link_state_db.get("_seq", {}).get(router_id, -1)):
            
            self.link_state_db[router_id] = lsa_data["neighbors"]
            self.link_state_db.setdefault("_seq", {})[router_id] = seq_num
            self.calculate_routing_table()
            
            for neighbor, (router, interface, metric) in self.connections.items():
                if neighbor != source:
                    packet = Packet(
                        source=self.name,
                        destination=neighbor,
                        payload=lsa_data,
                        type=PacketType.LS_ANNOUNCEMENT
                    )
                    self.forward_packet(packet, interface)
    
    def calculate_routing_table(self):
        """Вычисляет таблицу маршрутизации используя алгоритм Дейкстры"""
        distances = {router: float('inf') for router in self.link_state_db.keys() 
                    if router != "_seq"}
        distances[self.name] = 0
        previous = {}
        visited = set()
        pq = [(0, self.name)]
        
        while pq:
            current_dist, current_router = heapq.heappop(pq)
            
            if current_router in visited:
                continue
                
            visited.add(current_router)
            neighbors = self.link_state_db.get(current_router, {})
            
            for neighbor, metric in neighbors.items():
                if neighbor not in distances:
                    continue
                    
                distance = current_dist + metric
                
                if distance < distances[neighbor]:
                    distances[neighbor] = distance
                    previous[neighbor] = current_router
                    heapq.heappush(pq, (distance, neighbor))
        
        for target in distances:
            if target == self.name or distances[target] == float('inf'):
                continue
            
            next_hop = target
            while previous.get(next_hop) != self.name:
                next_hop = previous.get(next_hop, next_hop)
            
            interface = None
            for intf, (router, _, _) in self.connections.items():
                if router.name == next_hop:
                    interface = intf
                    break
            
            if interface:
                self.routing_table[target] = {
                    "next_hop": next_hop,
                    "interface": interface,
                    "metric": distances[target]
                }
    
    def find_route(self, destination: str) -> Optional[Dict]:
        """Находит маршрут до указанного узла"""
        if destination in self.connections:
            for intf, (router, _, metric) in self.connections.items():
                if router.name == destination:
                    return {
                        "next_hop": destination,
                        "interface": intf,
                        "metric": metric
                    }
        
        return self.routing_table.get(destination)
    
    def send_packet(self, destination: str, payload: Any) -> bool:
        """Отправляет пакет целевому узлу"""
        packet = Packet(
            source=self.name,
            destination=destination,
            payload=payload,
            path=[self.name]
        )
        return self.forward_packet(packet)
    
    def forward_packet(self, packet: Packet, incoming_interface: str = None) -> bool:
        """Пересылает пакет следующему узлу"""
        packet.ttl -= 1
        if packet.ttl <= 0:
            print(f"{self.name}: Packet TTL expired")
            return False
        
        if self.name not in packet.path:
            packet.path.append(self.name)
        
        print(f"{self.name}: Processing {packet}")
        
        if packet.type == PacketType.LS_ANNOUNCEMENT:
            self.receive_lsa(packet.payload, packet.source)
            return True
        
        if packet.destination == self.name:
            print(f"{self.name}: Packet received! Path: {' -> '.join(packet.path)}")
            print(f"Payload: {packet.payload}")
            return True
        
        route = self.find_route(packet.destination)
        if not route:
            print(f"{self.name}: No route to {packet.destination}")
            return False
        
        next_hop_router = self.connections[route["next_hop"]][0]
        print(f"{self.name}: Forwarding to {route['next_hop']} via {route['interface']}")
        
        return next_hop_router.forward_packet(packet, route["interface"])
    
    def get_routing_table_str(self) -> str:
        """Возвращает строковое представление таблицы маршрутизации"""
        result = [f"\n--- Routing Table for {self.name} ---"]
        result.append("Destination\tNext Hop\tInterface\tMetric")
        result.append("-" * 50)
        
        for dest, route in self.routing_table.items():
            result.append(f"{dest}\t{route['next_hop']}\t{route['interface']}\t\t{route['metric']}")
        
        return "\n".join(result)