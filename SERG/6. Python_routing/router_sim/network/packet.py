from dataclasses import dataclass

@dataclass
class Packet:
    src: str
    dst: str
    payload: str = ""
    ttl: int = 32

    def hop(self) -> None:
        if self.ttl <= 0:
            raise RuntimeError("TTL expired")
        self.ttl -= 1
