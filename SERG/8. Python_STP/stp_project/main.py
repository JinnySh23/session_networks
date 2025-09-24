from bridge import Bridge, Port
from stp import STP

def main():
    # Создаём мосты
    b1 = Bridge(priority=24576, mac="aa:bb:cc:00:00:01")
    b2 = Bridge(priority=32768, mac="aa:bb:cc:00:00:02")
    b3 = Bridge(priority=32768, mac="aa:bb:cc:00:00:03")

    # Добавляем порты
    b1.add_port(Port("p1"))
    b1.add_port(Port("p2"))

    b2.add_port(Port("p1"))
    b2.add_port(Port("p2"))

    b3.add_port(Port("p1"))
    b3.add_port(Port("p2"))

    # Запускаем STP
    stp = STP([b1, b2, b3])
    stp.run()

    # Печатаем результат
    for b in stp.bridges:
        print(f"\nBridge {b.bridge_id}")
        for p in b.ports:
            print(f"  {p}")

if __name__ == "__main__":
    main()
