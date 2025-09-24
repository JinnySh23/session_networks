# capture.py
from scapy.all import sniff, rdpcap
import threading
import time

class CaptureManager:
    def __init__(self, packet_callback, iface=None, bpf_filter=None):
        """
        packet_callback(pkt) будет вызвана для каждого пакета.
        iface и bpf_filter используются в live режиме.
        """
        self.packet_callback = packet_callback
        self.iface = iface
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._thread = None

    def _sniff_loop(self):
        sniff(prn=self.packet_callback, iface=self.iface, filter=self.bpf_filter, store=False,
              stop_filter=lambda p: self._stop_event.is_set())

    def start_live(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def replay_pcap(self, pcap_path, speed=1.0, inter_packet_delay=None):
        """
        Читает pcap и передает пакеты в callback.
        speed: множитель скорости (1.0 = как в pcap timestamps; >1 быстрее)
        inter_packet_delay: если указано, игнорирует timestamps и ставит фиксированную задержку (секунды) между пакетами.
        """
        pkts = rdpcap(pcap_path)
        if len(pkts) == 0:
            print("PCAP пустой:", pcap_path)
            return
        # Если pcap имеет временные метки, можно использовать их:
        base_ts = None
        for i, pkt in enumerate(pkts):
            # rdpcap сохраняет pkt.time если есть метки
            ts = getattr(pkt, 'time', None)
            if base_ts is None:
                base_ts = ts
                prev_ts = ts
            if inter_packet_delay is not None:
                delay = inter_packet_delay
            else:
                # рассчитать задержку по timestamps pcap
                delay = max(0, (ts - prev_ts) / max(1.0, speed))
            # sleep для имитации времени
            if delay > 0:
                time.sleep(delay)
            try:
                self.packet_callback(pkt)
            except Exception as e:
                print("Error in packet callback:", e)
            prev_ts = ts
