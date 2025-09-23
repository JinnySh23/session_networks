from typing import Dict
from router import Router

class Network:
    def __init__(self):
        self.routers: Dict[str, Router] = {}
    
    def add_router(self, name: str) -> Router:
        router = Router(name)
        self.routers[name] = router
        return router
    
    def get_router(self, name: str) -> Router:
        return self.routers.get(name)
    
    def update_all_link_states(self):
        """Обновляет состояние каналов на всех маршрутизаторах"""
        for router in self.routers.values():
            router.update_link_state()
    
    def simulate_link_failure(self, router1: str, router2: str):
        """Имитирует обрыв связи между двумя маршрутизаторами"""
        if router1 in self.routers and router2 in self.routers:
            r1 = self.routers[router1]
            r2 = self.routers[router2]
            
            if router2 in r1.connections:
                del r1.connections[router2]
            if router1 in r2.connections:
                del r2.connections[router1]
            
            print(f"Link between {router1} and {router2} failed!")
            self.update_all_link_states()
    
    def simulate_link_recovery(self, router1: str, router2: str, interface1: str, interface2: str, metric1: int = 1, metric2: int = 1):
        """Имитирует восстановление связи между двумя маршрутизаторами"""
        if router1 in self.routers and router2 in self.routers:
            r1 = self.routers[router1]
            r2 = self.routers[router2]
            
            r1.connections[r2.name] = (r2, interface1, metric1)
            r2.connections[r1.name] = (r1, interface2, metric2)
            
            print(f"Link between {router1} and {router2} recovered!")
            self.update_all_link_states()

def create_test_network():
    """Создает тестовую сеть с 6 маршрутизаторами"""
    network = Network()
    
    routers = []
    for i in range(1, 7):
        router = network.add_router(f"R{i}")
        router.add_interface(f"eth0", f"192.168.{i}.1")
        routers.append(router)
    
    # Создаем соединения (топология "кольцо" + дополнительные связи)
    network.routers["R1"].connect(network.routers["R2"], "eth1", "eth1", 1, 1)
    network.routers["R2"].connect(network.routers["R3"], "eth2", "eth1", 1, 1)
    network.routers["R3"].connect(network.routers["R4"], "eth2", "eth1", 1, 1)
    network.routers["R4"].connect(network.routers["R5"], "eth2", "eth1", 1, 1)
    network.routers["R5"].connect(network.routers["R6"], "eth2", "eth1", 1, 1)
    network.routers["R6"].connect(network.routers["R1"], "eth2", "eth2", 1, 1)
    
    # Дополнительные связи для альтернативных маршрутов
    network.routers["R1"].connect(network.routers["R4"], "eth3", "eth3", 3, 3)
    network.routers["R2"].connect(network.routers["R5"], "eth3", "eth3", 2, 2)
    
    return network