from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple
from .router import Router
from .link import Link
from .packet import Packet

@dataclass
class Topology:
    routers: Dict[str, Router]
    links: List[Link]

    @staticmethod
    def sample() -> "Topology":
        """Build a sample topology with >=6 routers and multiple paths."""
        names = ["A","B","C","D","E","F","G"]
        routers = {n: Router(n) for n in names}

        def connect(x: str, y: str, metric: float, ipx: str, ipy: str) -> Link:
            link = Link(routers[x], routers[y], metric=metric, up=True)
            routers[x].add_interface(name=f"{x}-{y}", ip=ipx, link=link)
            routers[y].add_interface(name=f"{y}-{x}", ip=ipy, link=link)
            return link

        links: List[Link] = []
        # Core ring A-B-C-D-E-F-A
        links.append(connect("A","B",1.0,"10.0.1.1/30","10.0.1.2/30"))
        links.append(connect("B","C",1.0,"10.0.2.1/30","10.0.2.2/30"))
        links.append(connect("C","D",5.0,"10.0.3.1/30","10.0.3.2/30"))  # a bit expensive
        links.append(connect("D","E",1.0,"10.0.4.1/30","10.0.4.2/30"))
        links.append(connect("E","F",1.0,"10.0.5.1/30","10.0.5.2/30"))
        links.append(connect("F","A",2.0,"10.0.6.1/30","10.0.6.2/30"))  # medium cost
        # Chords / alternate paths
        links.append(connect("B","E",2.0,"10.0.7.1/30","10.0.7.2/30"))
        links.append(connect("C","F",2.0,"10.0.8.1/30","10.0.8.2/30"))
        links.append(connect("A","D",3.0,"10.0.9.1/30","10.0.9.2/30"))
        # Spur to G from D (destination alternative)
        links.append(connect("D","G",1.0,"10.0.10.1/30","10.0.10.2/30"))

        topo = Topology(routers=routers, links=links)
        # Initial route computation
        for r in topo.routers.values():
            r.compute_routes(topo.routers)
        return topo

    def send(self, src: str, dst: str, payload: str = "") -> List[str]:
        pkt = Packet(src=src, dst=dst, payload=payload, ttl=32)
        log: List[str] = []
        ok = self.routers[src].forward(pkt, self.routers, log)
        if not ok:
            log.append("RESULT: Delivery failed")
        else:
            log.append("RESULT: Delivery success")
        return log

    def set_link_metric(self, a: str, b: str, metric: float) -> None:
        for ln in self.links:
            if {ln.a.name, ln.b.name} == {a, b}:
                ln.set_metric(metric)
        for r in self.routers.values():
            r.compute_routes(self.routers)

    def set_link_state(self, a: str, b: str, up: bool) -> None:
        for ln in self.links:
            if {ln.a.name, ln.b.name} == {a, b}:
                ln.set_state(up)
        for r in self.routers.values():
            r.compute_routes(self.routers)

    def routing_tables_snapshot(self) -> Dict[str, Dict[str, dict]]:
        snap = {}
        for name, r in self.routers.items():
            table = {}
            for dest, route in r.routing_table.items():
                table[dest] = {"next_hop": route.next_hop, "cost": route.cost, "path": route.path}
            snap[name] = table
        return snap
