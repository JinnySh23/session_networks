from network.topology import Topology

def print_table_snapshot(topo: Topology) -> None:
    snap = topo.routing_tables_snapshot()
    for r in sorted(snap):
        print(f"\nRouting table at {r}:")
        print(f"{'DEST':<5} {'NEXTHOP':<7} {'COST':<6} PATH")
        for dest, info in sorted(snap[r].items()):
            print(f"{dest:<5} {str(info['next_hop']):<7} {info['cost']:<6.2f} {'-'.join(info['path'])}")

def scenario():
    topo = Topology.sample()
    print("=== Initial routing tables ===")
    print_table_snapshot(topo)

    print("\n=== Send A -> F (initial) ===")
    for line in topo.send("A","F","hello F from A"):
        print(line)

    print("\n=== Increase cost on B-E to 50 (simulate congestion) ===")
    topo.set_link_metric("B","E",50.0)
    print_table_snapshot(topo)
    print("\n=== Send A -> F after metric change (should reroute) ===")
    for line in topo.send("A","F","reroute test"):
        print(line)

    print("\n=== Bring down link C-F (failure) ===")
    topo.set_link_state("C","F",False)
    print_table_snapshot(topo)
    print("\n=== Send A -> G after failure (still should work via A-D-G) ===")
    for line in topo.send("A","G","to G despite failure"):
        print(line)

if __name__ == "__main__":
    scenario()
