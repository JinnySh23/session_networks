class STP:
    def __init__(self, bridges):
        self.bridges = bridges
        self.root_bridge = None

    def elect_root_bridge(self):
        """Выбор корневого моста (Root Bridge)"""
        self.root_bridge = min(self.bridges, key=lambda b: b.bridge_id)
        print(f"Root Bridge выбран: {self.root_bridge.bridge_id}")

    def assign_roles(self):
        """Назначение ролей портам"""
        for bridge in self.bridges:
            if bridge == self.root_bridge:
                # У корневого моста все порты — Designated
                for p in bridge.ports:
                    p.role = "Designated"
                    p.state = "FORWARDING"
            else:
                # Выбор Root Port (порт с наименьшей стоимостью пути до Root Bridge)
                if bridge.ports:
                    root_port = min(bridge.ports, key=lambda p: p.cost)
                    root_port.role = "Root"
                    root_port.state = "FORWARDING"
                    # Остальные порты — Blocked
                    for p in bridge.ports:
                        if p != root_port:
                            p.role = "Blocked"
                            p.state = "BLOCKED"

    def run(self):
        self.elect_root_bridge()
        self.assign_roles()
