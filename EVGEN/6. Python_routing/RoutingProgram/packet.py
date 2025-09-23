from dataclasses import dataclass, field
from typing import Any, List
from enum import Enum

class PacketType(Enum):
    DATA = "DATA"
    LS_ANNOUNCEMENT = "LS_ANNOUNCEMENT"

@dataclass
class Packet:
    source: str
    destination: str
    payload: Any
    type: PacketType = PacketType.DATA
    ttl: int = 64
    path: List[str] = field(default_factory=list)
    
    def __str__(self):
        return f"Packet({self.source} -> {self.destination}, type={self.type.name}, ttl={self.ttl})"