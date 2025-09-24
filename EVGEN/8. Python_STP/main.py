from stp_classes import STPSwitch
import time
import threading

class STPSimulation:
    def __init__(self):
        self.switches = {}
        self.running = False
    
    def create_switch(self, bridge_id: int, mac_address: str, num_ports: int = 4):
        """Create a new switch with specified number of ports"""
        switch = STPSwitch(bridge_id, mac_address)
        
        # Add ports with unique MAC addresses
        for i in range(1, num_ports + 1):
            port_mac = f"{mac_address}:{i:02d}"
            switch.add_port(i, port_mac, cost=10)
        
        self.switches[bridge_id] = switch
        return switch
    
    def connect_switches(self, switch1_id: int, port1_id: int, 
                        switch2_id: int, port2_id: int):
        """Connect two switches together"""
        if switch1_id in self.switches and switch2_id in self.switches:
            switch1 = self.switches[switch1_id]
            switch2 = self.switches[switch2_id]
            switch1.connect_to(port1_id, switch2, port2_id)
            print(f"Connected Switch {switch1_id} Port {port1_id} to Switch {switch2_id} Port {port2_id}")
    
    def start_simulation(self):
        """Start the STP simulation"""
        self.running = True
        print("Starting STP Simulation...")
        
        # Start STP on all switches
        for switch_id, switch in self.switches.items():
            switch.start_stp()
            print(f"Switch {switch_id} STP started")
        
        # Monitor thread to display status periodically
        def monitor():
            while self.running:
                time.sleep(5)
                self.print_network_status()
        
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def stop_simulation(self):
        """Stop the STP simulation"""
        self.running = False
        for switch in self.switches.values():
            switch.stop_stp()
        print("STP Simulation stopped")
    
    def print_network_status(self):
        """Print status of all switches in the network"""
        print("\n" + "="*50)
        print("NETWORK STATUS")
        print("="*50)
        
        for switch_id, switch in self.switches.items():
            switch.print_status()
        
        print("="*50)

def main():
    """Main function to demonstrate STP behavior"""
    simulation = STPSimulation()
    
    # Create switches (lower bridge ID has higher priority)
    print("Creating switches...")
    switch1 = simulation.create_switch(100, "00:AA:BB:CC:DD:01")  # Lowest ID - should become root
    switch2 = simulation.create_switch(200, "00:AA:BB:CC:DD:02")
    switch3 = simulation.create_switch(300, "00:AA:BB:CC:DD:03")
    
    # Connect switches in a triangle topology (will create a loop)
    print("\nConnecting switches...")
    simulation.connect_switches(100, 1, 200, 1)  # Switch1 Port1 <-> Switch2 Port1
    simulation.connect_switches(100, 2, 300, 1)  # Switch1 Port2 <-> Switch3 Port1
    simulation.connect_switches(200, 2, 300, 2)  # Switch2 Port2 <-> Switch3 Port2
    
    # Start simulation
    simulation.start_simulation()
    
    try:
        # Let the simulation run for 30 seconds
        print("\nSimulation running for 30 seconds...")
        print("Press Ctrl+C to stop early")
        time.sleep(30)
        
    except KeyboardInterrupt:
        print("\nSimulation interrupted by user")
    
    finally:
        simulation.stop_simulation()

def demo_network_changes():
    """Demonstrate how STP handles network changes"""
    print("\n" + "="*60)
    print("DEMONSTRATING NETWORK CHANGES")
    print("="*60)
    
    simulation = STPSimulation()
    
    # Create a more complex network
    switches = {}
    for i, bridge_id in enumerate([100, 200, 300, 400]):
        switches[bridge_id] = simulation.create_switch(bridge_id, f"00:AA:BB:CC:DD:{bridge_id:02d}")
    
    # Create a network with multiple loops
    connections = [
        (100, 1, 200, 1),
        (100, 2, 300, 1),
        (200, 2, 400, 1),
        (300, 2, 400, 2),
        (200, 3, 300, 3)  # This creates a loop
    ]
    
    for conn in connections:
        simulation.connect_switches(*conn)
    
    simulation.start_simulation()
    
    try:
        # Let STP converge
        print("Waiting for STP to converge...")
        time.sleep(15)
        
        # Simulate a link failure
        print("\n>>> Simulating link failure between Switch 100 and Switch 200 <<<")
        # In a real implementation, we would break the connection here
        # For simulation, we'll just print the message
        time.sleep(10)
        
        # Show how STP recovers
        print("\n>>> STP should have recalculated the tree <<<")
        time.sleep(10)
        
    except KeyboardInterrupt:
        pass
    finally:
        simulation.stop_simulation()

if __name__ == "__main__":
    print("STP Protocol Simulation")
    print("=" * 40)
    
    # Run basic demo
    main()
    
    # Uncomment to run the network changes demo
    # demo_network_changes()