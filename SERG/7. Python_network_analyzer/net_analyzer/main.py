# main.py
from capture import CaptureManager
from detectors import (SynFloodDetector, PortScanDetector, ArpDetector, DhcpDetector,
                       DnsSpoofDetector, FragmentationDetector, IcmpDetector, HttpSlowPostDetector)
from alerts import AlertManager
from scapy.all import Ether, IP, ARP, TCP, UDP, ICMP, DNS, DHCP
import argparse

def packet_handler(pkt):
    # feed packet to all detectors
    for det in detectors:
        try:
            det.feed(pkt)
        except Exception as e:
            print("Detector error:", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Anomaly Detector")
    parser.add_argument("--iface", "-i", help="Interface to sniff (e.g., eth0)", default=None)
    parser.add_argument("--filter", "-f", help="BPF filter", default=None)
    args = parser.parse_args()

    alert_mgr = AlertManager()
    detectors = [
        SynFloodDetector(alert_mgr),
        PortScanDetector(alert_mgr),
        ArpDetector(alert_mgr),
        DhcpDetector(alert_mgr),
        DnsSpoofDetector(alert_mgr),
        FragmentationDetector(alert_mgr),
        IcmpDetector(alert_mgr),
        HttpSlowPostDetector(alert_mgr)
    ]

    cap = CaptureManager(packet_handler, iface=args.iface, bpf_filter=args.filter)
    print("Starting capture. Ctrl+C to stop.")
    try:
        cap.start()
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
        cap.stop()
