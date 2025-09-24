# detectors.py
import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP
from utils import SlidingWindow
from config import *
from alerts import AlertManager
from collections import defaultdict, Counter

class BaseDetector:
    def __init__(self, alert_manager, window_seconds=WINDOW_SECONDS):
        self.alerts = alert_manager
        self.window_seconds = window_seconds

class SynFloodDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.syn_window = SlidingWindow(WINDOW_SECONDS)
        self.syn_by_src = defaultdict(int)
        self.synacks_by_src = defaultdict(int)
        self.ack_by_src = defaultdict(int)

    def feed(self, pkt):
        now = time.time()
        if TCP in pkt:
            flags = pkt[TCP].flags
            src = pkt[IP].src if IP in pkt else pkt.src
            if 'S' in flags and 'A' not in flags:  # SYN without ACK
                self.syn_window.add(now, src)
                self.syn_by_src[src] += 1
            elif 'SA' in flags:  # SYN-ACK
                self.synacks_by_src[src] += 1
            elif 'A' in flags and 'S' not in flags:
                self.ack_by_src[src] += 1

            # periodic check
            if self.syn_window.count() >= SYN_THRESHOLD or len(self.syn_by_src) >= SYN_SRC_UNIQUE_THRESHOLD:
                self.alerts.send('syn_flood', f"SYN flood suspected: {self.syn_window.count()} SYNs in last {WINDOW_SECONDS}s from {len(self.syn_by_src)} sources")

class PortScanDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.calls = defaultdict(lambda: SlidingWindow(WINDOW_SECONDS))  # src -> SlidingWindow of dst:port
        self.ports_seen = defaultdict(lambda: defaultdict(set))  # src -> dst -> set(ports)

    def feed(self, pkt):
        now = time.time()
        src = pkt[IP].src if IP in pkt else None
        dst = pkt[IP].dst if IP in pkt else None
        port = None
        if TCP in pkt:
            port = pkt[TCP].dport
        elif UDP in pkt:
            port = pkt[UDP].dport
        if not src or not dst or not port:
            return
        self.ports_seen[src][dst].add(port)
        total_ports = sum(len(s) for s in self.ports_seen[src].values())
        if total_ports >= PORTSCAN_PORTS_THRESHOLD:
            self.alerts.send('portscan', f"Port scanning suspected from {src}: touched {total_ports} ports in last {WINDOW_SECONDS}s")

class ArpDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.ip_mac_history = defaultdict(lambda: SlidingWindow(WINDOW_SECONDS))  # ip -> windows of macs (timestamp, mac)
        self.garp_count = defaultdict(int)

    def feed(self, pkt):
        if ARP in pkt:
            now = time.time()
            op = pkt[ARP].op
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            if op == 2:  # is-at (reply), could be gratuitous as well
                # store mac for ip
                self.ip_mac_history[src_ip].add(now, src_mac)
                macs = [m for _, m in self.ip_mac_history[src_ip].items()]
                if len(set(macs)) >= ARP_CONFLICT_THRESHOLD:
                    self.alerts.send('arp_conflict', f"ARP conflict: IP {src_ip} seen with multiple MACs: {set(macs)}")
                # detect gratuitous: packet has psrc==pdst or opcode==2 and no prior request
                if pkt[ARP].psrc == pkt[ARP].pdst:
                    self.garp_count[src_ip] += 1
                    if self.garp_count[src_ip] >= GARP_THRESHOLD:
                        self.alerts.send('garp_dos', f"Many gratuitous ARP from IP {src_ip} (count={self.garp_count[src_ip]})")

class DhcpDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.requests_window = SlidingWindow(WINDOW_SECONDS)
        self.mac_counter = Counter()

    def feed(self, pkt):
        if DHCP in pkt:
            now = time.time()
            msgtypes = pkt[DHCP].options
            # rough heuristic: count DHCPDISCOVER/REQUEST by MAC
            client_mac = pkt.src
            self.requests_window.add(now, client_mac)
            self.mac_counter[client_mac] += 1
            if self.requests_window.count() >= DHCP_REQUESTS_THRESHOLD or len(self.mac_counter) >= DHCP_UNIQUE_MAC_THRESHOLD:
                self.alerts.send('dhcp_starvation', f"DHCP starvation suspected: {self.requests_window.count()} DHCP messages, unique MACs {len(self.mac_counter)}")

class DnsSpoofDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        # map: query_name -> set of answers observed within window
        self.answers = defaultdict(lambda: SlidingWindow(WINDOW_SECONDS))

    def feed(self, pkt):
        if DNS in pkt and pkt[DNS].qr == 1:  # DNS response
            now = time.time()
            qname = None
            if pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode() if isinstance(pkt[DNS].qd.qname, bytes) else pkt[DNS].qd.qname
            answers = []
            for i in range(pkt[DNS].ancount):
                rr = pkt[DNS].an[i]
                if hasattr(rr, 'rdata'):
                    answers.append(rr.rdata)
            if qname:
                self.answers[qname].add(now, tuple(answers))
                # collect unique answer tuples
                seen = set([a for _, a in self.answers[qname].items()])
                if len(seen) >= DNS_MULTIPLE_ANSWERS_THRESHOLD:
                    self.alerts.send('dns_spoof', f"Possible DNS spoofing for {qname}: multiple different answers observed: {seen}")

class FragmentationDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.frag_count = SlidingWindow(WINDOW_SECONDS)

    def feed(self, pkt):
        if IP in pkt:
            ip = pkt[IP]
            # MF flag or frag offset > 0 indicates fragment
            if ip.flags.MF or ip.frag > 0:
                self.frag_count.add(time.time(), pkt)
                if self.frag_count.count() >= FRAG_THRESHOLD:
                    self.alerts.send('ip_fragment', f"High number of IP fragments: {self.frag_count.count()} in last {WINDOW_SECONDS}s")

class IcmpDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        self.icmp_replies = defaultdict(lambda: SlidingWindow(WINDOW_SECONDS))  # dst -> window of sources

    def feed(self, pkt):
        if ICMP in pkt:
            icmp = pkt[ICMP]
            if icmp.type == 0:  # echo-reply
                dst = pkt[IP].dst
                self.icmp_replies[dst].add(time.time(), pkt[IP].src)
                if self.icmp_replies[dst].count() >= ICMP_REPLY_THRESHOLD:
                    self.alerts.send('smurf', f"Possible Smurf amplification toward {dst}: {self.icmp_replies[dst].count()} icmp replies")

class HttpSlowPostDetector(BaseDetector):
    def __init__(self, alert_manager):
        super().__init__(alert_manager)
        # track TCP connections with suspicious POST headers
        self.suspicious_posts = {}  # (src, sport, dst, dport) -> {start_ts, content_length, bytes_seen}
        self.last_cleanup = time.time()

    def feed(self, pkt):
        now = time.time()
        # naive HTTP detection: payload contains "POST "
        if TCP in pkt and pkt[TCP].payload:
            payload = bytes(pkt[TCP].payload)
            key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            if b"POST " in payload:
                # try to parse Content-Length
                cl = 0
                try:
                    s = payload.decode(errors='ignore')
                    for line in s.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            cl = int(line.split(":")[1].strip())
                            break
                except Exception:
                    pass
                self.suspicious_posts[key] = {
                    'start': now,
                    'content_length': cl,
                    'bytes': len(payload),
                    'last_seen': now
                }
            elif key in self.suspicious_posts:
                entry = self.suspicious_posts[key]
                entry['bytes'] += len(payload)
                entry['last_seen'] = now
                duration = now - entry['start']
                if entry['content_length'] > 0:
                    # if content-length much larger than bytes transferred and connection long
                    if duration >= HTTP_SLOW_DURATION and entry['bytes'] < entry['content_length'] * 0.2:
                        self.alerts.send('http_slow_post', f"Slow HTTP POST suspected from {key[0]}->{key[2]}:{key[3]} duration {duration:.1f}s bytes {entry['bytes']} / {entry['content_length']}")
        # cleanup old entries occasionally
        if now - self.last_cleanup > 5:
            to_del = []
            for k, v in self.suspicious_posts.items():
                if now - v['last_seen'] > 60:
                    to_del.append(k)
            for k in to_del:
                del self.suspicious_posts[k]
            self.last_cleanup = now
