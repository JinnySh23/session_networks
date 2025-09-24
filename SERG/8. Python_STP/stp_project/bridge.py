import uuid

class Port:
    def __init__(self, name, cost=1):
        self.name = name
        self.cost = cost
        self.role = None  # Root, Designated, Blocked
        self.state = "DOWN"
        self.link = None  # ссылка на другой порт

    def __repr__(self):
        return f"<Port {self.name} role={self.role} state={self.state}>"

class Bridge:
    def __init__(self, priority=32768, mac=None):
        self.priority = priority
        self.mac = mac or str(uuid.uuid4())[:12]
        self.bridge_id = (self.priority, self.mac)
        self.ports = []

    def add_port(self, port: Port):
        self.ports.append(port)

    def __repr__(self):
        return f"<Bridge {self.bridge_id} ports={len(self.ports)}>"
