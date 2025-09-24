import time
import threading
from enum import Enum
from typing import List, Dict, Optional

class PortState(Enum):
    BLOCKING = "BLOCKING"
    LISTENING = "LISTENING"
    LEARNING = "LEARNING"
    FORWARDING = "FORWARDING"
    DISABLED = "DISABLED"

class STPMessage:
    def __init__(self, root_bridge_id: int, sender_bridge_id: int, 
                 path_cost: int, port_id: int):
        self.root_bridge_id = root_bridge_id
        self.sender_bridge_id = sender_bridge_id
        self.path_cost = path_cost
        self.port_id = port_id
        self.timestamp = time.time()
    
    def __str__(self):
        return f"STP Message: Root={self.root_bridge_id}, Sender={self.sender_bridge_id}, Cost={self.path_cost}"

class STPPort:
    def __init__(self, port_id: int, mac_address: str, cost: int = 10):
        self.port_id = port_id
        self.mac_address = mac_address
        self.cost = cost
        self.state = PortState.BLOCKING
        self.connected_to = None  # Connected switch and port
        self.designated_root_id = float('inf')
        self.designated_bridge_id = float('inf')
        self.designated_port_id = float('inf')
        self.message_age = 0
    
    def update_state(self, new_state: PortState):
        """Update port state with state transition rules"""
        valid_transitions = {
            PortState.BLOCKING: [PortState.LISTENING, PortState.DISABLED],
            PortState.LISTENING: [PortState.LEARNING, PortState.BLOCKING, PortState.DISABLED],
            PortState.LEARNING: [PortState.FORWARDING, PortState.BLOCKING, PortState.DISABLED],
            PortState.FORWARDING: [PortState.BLOCKING, PortState.DISABLED],
            PortState.DISABLED: [PortState.BLOCKING]
        }
        
        if new_state in valid_transitions.get(self.state, []):
            print(f"Port {self.port_id}: {self.state.value} -> {new_state.value}")
            self.state = new_state
            return True
        return False
    
    def receive_bpdu(self, message: STPMessage) -> bool:
        """Process received BPDU message"""
        if self.state == PortState.DISABLED:
            return False
        
        # STP decision process
        if message.root_bridge_id < self.designated_root_id:
            return True
        elif message.root_bridge_id == self.designated_root_id:
            if message.path_cost + self.cost < self.designated_root_id:
                return True
            elif (message.path_cost + self.cost == self.designated_root_id and
                  message.sender_bridge_id < self.designated_bridge_id):
                return True
        return False

class STPSwitch:
    def __init__(self, bridge_id: int, mac_address: str):
        self.bridge_id = bridge_id
        self.mac_address = mac_address
        self.ports: Dict[int, STPPort] = {}
        self.root_bridge_id = bridge_id  # Initially consider itself as root
        self.root_path_cost = 0
        self.root_port_id = None
        self.is_root_bridge = True
        self.hello_time = 2 # seconds
        self.max_age = 20  # seconds
        self.forward_delay = 15  # seconds
        self.running = False
        self.thread = None
    
    def add_port(self, port_id: int, mac_address: str, cost: int = 10):
        """Add a port to the switch"""
        self.ports[port_id] = STPPort(port_id, mac_address, cost)
    
    def connect_to(self, port_id: int, other_switch: 'STPSwitch', other_port_id: int):
        """Connect this switch to another switch"""
        if port_id in self.ports and other_port_id in other_switch.ports:
            self.ports[port_id].connected_to = (other_switch, other_port_id)
            other_switch.ports[other_port_id].connected_to = (self, port_id)
    
    def send_bpdu(self, port_id: int):
        """Send BPDU message through specified port"""
        if port_id not in self.ports:
            return
        
        port = self.ports[port_id]
        if port.state == PortState.DISABLED:
            return
        
        message = STPMessage(
            root_bridge_id=self.root_bridge_id,
            sender_bridge_id=self.bridge_id,
            path_cost=self.root_path_cost,
            port_id=port_id
        )
        
        if port.connected_to:
            other_switch, other_port = port.connected_to
            print(f"Switch {self.bridge_id} sending BPDU to Switch {other_switch.bridge_id}")
            other_switch.receive_bpdu(other_port, message)
    
    def receive_bpdu(self, port_id: int, message: STPMessage):
        """Receive and process BPDU message"""
        if port_id not in self.ports:
            return
        
        port = self.ports[port_id]
        
        if port.receive_bpdu(message):
            # Update bridge information
            new_root_path_cost = message.path_cost + port.cost
            
            if (message.root_bridge_id < self.root_bridge_id or
                (message.root_bridge_id == self.root_bridge_id and 
                 new_root_path_cost < self.root_path_cost)):
                
                self.root_bridge_id = message.root_bridge_id
                self.root_path_cost = new_root_path_cost
                self.root_port_id = port_id
                self.is_root_bridge = (self.bridge_id == self.root_bridge_id)
                
                # Update port designated values
                port.designated_root_id = message.root_bridge_id
                port.designated_bridge_id = self.bridge_id
                port.designated_port_id = port_id
                
                self.recalculate_spanning_tree()
    
    def recalculate_spanning_tree(self):
        """Recalculate spanning tree after topology change"""
        print(f"Switch {self.bridge_id} recalculating spanning tree...")
        
        # Determine root port
        root_port_candidates = []
        for port_id, port in self.ports.items():
            if port.designated_root_id == self.root_bridge_id:
                root_port_candidates.append((port_id, port.root_path_cost))
        
        if root_port_candidates:
            root_port_candidates.sort(key=lambda x: x[1])  # Sort by path cost
            self.root_port_id = root_port_candidates[0][0]
        
        # Update port states
        for port_id, port in self.ports.items():
            if port_id == self.root_port_id:
                # Root port should be forwarding
                if port.state != PortState.FORWARDING:
                    port.update_state(PortState.LISTENING)
                    # In real STP, there would be timers for state transitions
                    port.update_state(PortState.LEARNING)
                    port.update_state(PortState.FORWARDING)
            elif (port.designated_bridge_id == self.bridge_id and 
                  port.designated_port_id == port_id):
                # Designated port should be forwarding
                if port.state != PortState.FORWARDING:
                    port.update_state(PortState.LISTENING)
                    port.update_state(PortState.LEARNING)
                    port.update_state(PortState.FORWARDING)
            else:
                # Blocking port
                if port.state != PortState.BLOCKING:
                    port.update_state(PortState.BLOCKING)
    
    def start_stp(self):
        """Start the STP protocol"""
        self.running = True
        self.thread = threading.Thread(target=self._stp_loop)
        self.thread.daemon = True
        self.thread.start()
    
    def stop_stp(self):
        """Stop the STP protocol"""
        self.running = False
        if self.thread:
            self.thread.join()
    
    def _stp_loop(self):
        """Main STP loop - sends BPDUs periodically"""
        while self.running:
            if self.is_root_bridge:
                # Root bridge sends BPDUs on all designated ports
                for port_id in self.ports:
                    if self.ports[port_id].state == PortState.FORWARDING:
                        self.send_bpdu(port_id)
            else:
                # Non-root bridges forward BPDUs through root port
                if self.root_port_id:
                    self.send_bpdu(self.root_port_id)
            
            time.sleep(self.hello_time)
    
    def get_port_states(self) -> Dict[int, str]:
        """Get current port states"""
        return {port_id: port.state.value for port_id, port in self.ports.items()}
    
    def print_status(self):
        """Print current switch status"""
        print(f"\n=== Switch {self.bridge_id} Status ===")
        print(f"Root Bridge: {self.root_bridge_id}")
        print(f"Is Root: {self.is_root_bridge}")
        print(f"Root Path Cost: {self.root_path_cost}")
        print(f"Root Port: {self.root_port_id}")
        print("Port States:")
        for port_id, port in self.ports.items():
            print(f"  Port {port_id}: {port.state.value}")