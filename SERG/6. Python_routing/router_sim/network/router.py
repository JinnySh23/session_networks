from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import math

@dataclass
class Interface:
    name: str
    ip: str
    link: "Link"

@dataclass
class Route:
    destination: str
    next_hop: Optional[str]  # None for directly connected / self
    cost: float
    path: List[str]  # full path from self to destination (inclusive)

@dataclass
class Router:
    name: str
    interfaces: List[Interface] = field(default_factory=list)
    routing_table: Dict[str, Route] = field(default_factory=dict, init=False)

    def add_interface(self, name: str, ip: str, link: "Link") -> None:
        self.interfaces.append(Interface(name=name, ip=ip, link=link))

    @property
    def neighbors(self) -> Dict[str, Tuple["Router", float]]:
        """Return neighbor name -> (router, cost) for UP links."""
        result = {}
        for iface in self.interfaces:
            if iface.link.up:
                other = iface.link.other(self)
                result[other.name] = (other, iface.link.metric)
        return result

    def compute_routes(self, all_routers: Dict[str, "Router"]) -> None:
        """Simple Dijkstra over routers as graph nodes using link metrics."""
        # Distances and previous-hop map
        dist = {r: math.inf for r in all_routers}
        prev = {r: None for r in all_routers}  # type: Dict[str, Optional[str]]
        dist[self.name] = 0.0
        visited = set()

        while len(visited) < len(all_routers):
            # pick unvisited node with smallest dist
            u = None
            u_cost = math.inf
            for r, c in dist.items():
                if r not in visited and c < u_cost:
                    u, u_cost = r, c
            if u is None:
                break
            visited.add(u)
            # relax edges
            u_router = all_routers[u]
            for v_name, (v_router, edge_cost) in u_router.neighbors.items():
                if v_name in visited:
                    continue
                alt = dist[u] + edge_cost
                if alt < dist[v_name]:
                    dist[v_name] = alt
                    prev[v_name] = u

        # build routing table
        table: Dict[str, Route] = {}
        for dest in all_routers:
            if dest == self.name:
                table[dest] = Route(destination=dest, next_hop=None, cost=0.0, path=[self.name])
                continue
            if math.isinf(dist[dest]):
                # unreachable
                continue
            # reconstruct path
            path = []
            cur = dest
            while cur is not None:
                path.append(cur)
                cur = prev[cur]
            path.reverse()  # now from self -> dest
            if path[0] != self.name:
                # Not reachable (shouldn't happen if graph traversal began at self)
                continue
            next_hop = path[1] if len(path) > 1 else None
            table[dest] = Route(destination=dest, next_hop=next_hop, cost=dist[dest], path=path)

        self.routing_table = table

    def forward(self, pkt: "Packet", all_routers: Dict[str, "Router"], log: List[str]) -> bool:
        """Process a packet at this router. Returns True if delivered, False if dropped."""
        log.append(f"[{self.name}] Received packet (ttl={pkt.ttl}) dst={pkt.dst}")
        if pkt.ttl <= 0:
            log.append(f"[{self.name}] DROP: TTL expired")
            return False
        if pkt.dst == self.name:
            log.append(f"[{self.name}] DELIVERED payload='{pkt.payload}'")
            return True
        # ensure routing table is available
        if not self.routing_table or pkt.dst not in self.routing_table:
            self.compute_routes(all_routers)
        route = self.routing_table.get(pkt.dst)
        if route is None:
            log.append(f"[{self.name}] DROP: No route to {pkt.dst}")
            return False
        next_name = route.next_hop
        if next_name is None:
            # same node (should have matched above)
            log.append(f"[{self.name}] DROP: Routing inconsistency for {pkt.dst}")
            return False
        # find outgoing interface/link to that neighbor and ensure it's up
        if next_name not in self.neighbors:
            log.append(f"[{self.name}] DROP: Next hop {next_name} not reachable (link down?)")
            return False
        pkt.hop()
        log.append(f"[{self.name}] FORWARD -> {next_name} via cost={route.cost:.2f} path={'-'.join(route.path)}")
        return self.neighbors[next_name][0].forward(pkt, all_routers, log)
