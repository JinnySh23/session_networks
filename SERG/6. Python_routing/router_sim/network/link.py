from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Link:
    """Bidirectional link between two routers with a metric (cost)."""
    a: "Router"
    b: "Router"
    metric: float = 1.0
    up: bool = True

    def other(self, node: "Router") -> "Router":
        if node is self.a:
            return self.b
        elif node is self.b:
            return self.a
        else:
            raise ValueError("Node not part of this link")

    def set_metric(self, metric: float) -> None:
        if metric <= 0:
            raise ValueError("Metric must be positive")
        self.metric = metric

    def set_state(self, up: bool) -> None:
        self.up = up
