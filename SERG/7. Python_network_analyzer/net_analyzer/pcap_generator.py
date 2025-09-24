# pcap_generator.py
"""
Генератор PCAP-файлов с характерными шаблонами трафика для безопасного тестирования.

Примеры генерации:
python3 pcap_generator.py --synflood out_syn.pcap --count 1000 --src 10.0.0.5 --dst 10.0.0.10
python3 pcap_generator.py --arp_spoof out_arp.pcap
python3 pcap_generator.py --dhcp_starvation out_dhcp.pcap
"""
from scapy.all import Ether, IP, TCP, UDP, ARP, ICMP, DNS, DNSRR, DNSQR, BOOTP, DHCP, wrpcap
import argparse
import random
import time

def gen_syn_flood(count=1000, src="10.0.0.5", dst="10.0.0.10", sport_base=40000, dport=80):
    pkts = []
    for i in range(count):
        sport = sport_base + (i % 1000)
        seq = random.randint(0, 0xFFFFFFFF)
        pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=seq)
        # set realistic timestamp - scapy wrpcap will keep pkt.time if set
        pkt.time = time.time() + i * 0.0001
        pkts.append(pkt)
    return pkts

def gen_arp_spoof(count=200, victim_ip="10.0.0.10", fake_macs=None):
    if fake_macs is None:
        fake_macs = [ "02:00:00:00:%02x:%02x" % (random.randint(0,255), random.randint(0,255)) for _ in range(5) ]
    pkts = []
    for i in range(count):
        mac = random.choice(fake_macs)
        # ARP reply (is-at) claiming victim_ip is at fake mac
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=victim_ip, hwsrc=mac, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff")
        pkt.time = time.time() + i * 0.01
        pkts.append(pkt)
    return pkts

def gen_gratuitous_arp(count=50, ip="10.0.0.10", mac="02:aa:bb:cc:dd:ee"):
    pkts = []
    for i in range(count):
        pkt = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, psrc=ip, hwsrc=mac, pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
        pkt.time = time.time() + i * 0.2
        pkts.append(pkt)
    return pkts

def gen_dhcp_starvation(count=300, src_mac_base="02:00:00:00:00:", src_ip="0.0.0.0", dst="255.255.255.255"):
    pkts = []
    for i in range(count):
        mac = src_mac_base + ("%02x" % (i % 256))
        # DHCP Discover broadcast
        ether = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        ip = IP(src=src_ip, dst=dst)
        udp = UDP(sport=68, dport=67)
        bootp = BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=random.randint(1,0xFFFFFFFF))
        dhcp = DHCP(options=[("message-type","discover"), "end"])
        pkt = ether/ip/udp/bootp/dhcp
        pkt.time = time.time() + i * 0.01
        pkts.append(pkt)
    return pkts

def gen_port_scan(src="10.0.0.5", dst="10.0.0.10", ports=range(1,600)):
    pkts = []
    i = 0
    for p in ports:
        pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=40000 + (i%1000), dport=p, flags="S")
        pkt.time = time.time() + i * 0.001
        pkts.append(pkt)
        i += 1
    return pkts

def gen_icmp_smurf(broadcast="10.0.0.255", victim="10.0.0.10", count=300):
    pkts = []
    for i in range(count):
        pkt = Ether()/IP(src=victim, dst=broadcast)/ICMP(type=8)/b"ping"
        pkt.time = time.time() + i * 0.01
        pkts.append(pkt)
    return pkts

def gen_ip_fragments(src="10.0.0.5", dst="10.0.0.10", total_fragments=50):
    # create a large payload and split into fragments
    payload = b"A" * 2000
    # first fragment
    pkts = []
    mtu_payload = 400
    frag_id = random.randint(1, 0xFFFF)
    offset = 0
    idx = 0
    while offset < len(payload):
        part = payload[offset:offset+mtu_payload]
        mf = 1 if (offset + mtu_payload) < len(payload) else 0
        ip = IP(src=src, dst=dst, id=frag_id, flags="MF" if mf else 0, frag=offset//8)
        pkt = Ether()/ip/part
        pkt.time = time.time() + idx * 0.001
        pkts.append(pkt)
        offset += mtu_payload
        idx += 1
    return pkts

def gen_dns_spoof_like(qname="example.test", different_answers=None, count=10):
    if different_answers is None:
        different_answers = ["1.2.3.4", "5.6.7.8", "9.9.9.9"]
    pkts = []
    for i in range(count):
        ans = random.choice(different_answers)
        dns = DNS(id=random.randint(0,65535), qr=1, qd=DNSQR(qname=qname), ancount=1, an=DNSRR(rrname=qname, rdata=ans))
        pkt = Ether()/IP(src="8.8.8.8", dst="10.0.0.10")/UDP(sport=53, dport=33333)/dns
        pkt.time = time.time() + i * 0.01
        pkts.append(pkt)
    return pkts

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--synflood", help="выходной pcap для SYN-flood", default=None)
    parser.add_argument("--arp_spoof", help="выходной pcap для ARP spoof", default=None)
    parser.add_argument("--garp", help="gratuitous arp pcap", default=None)
    parser.add_argument("--dhcp_starvation", help="out pcap for dhcp starvation", default=None)
    parser.add_argument("--portscan", help="out pcap for portscan", default=None)
    parser.add_argument("--icmp_smurf", help="out pcap for icmp smurf", default=None)
    parser.add_argument("--fragments", help="out pcap for ip fragments", default=None)
    parser.add_argument("--dns_spoof", help="out pcap for dns spoof like", default=None)
    parser.add_argument("--count", type=int, default=1000)
    args = parser.parse_args()

    all_pkts = []
    if args.synflood:
        print("Generating SYN flood ->", args.synflood)
        all_pkts += gen_syn_flood(count=args.count)
        wrpcap(args.synflood, all_pkts)
        all_pkts = []

    if args.arp_spoof:
        print("Generating ARP spoof ->", args.arp_spoof)
        all_pkts += gen_arp_spoof(count=200)
        wrpcap(args.arp_spoof, all_pkts)
        all_pkts = []

    if args.garp:
        print("Generating Gratuitous ARP ->", args.garp)
        all_pkts += gen_gratuitous_arp(count=50)
        wrpcap(args.garp, all_pkts)
        all_pkts = []

    if args.dhcp_starvation:
        print("Generating DHCP starvation ->", args.dhcp_starvation)
        all_pkts += gen_dhcp_starvation(count=300)
        wrpcap(args.dhcp_starvation, all_pkts)
        all_pkts = []

    if args.portscan:
        print("Generating portscan ->", args.portscan)
        all_pkts += gen_port_scan(ports=range(1, args.count))
        wrpcap(args.portscan, all_pkts)
        all_pkts = []

    if args.icmp_smurf:
        print("Generating ICMP smurf ->", args.icmp_smurf)
        all_pkts += gen_icmp_smurf(count=args.count)
        wrpcap(args.icmp_smurf, all_pkts)
        all_pkts = []

    if args.fragments:
        print("Generating IP fragments ->", args.fragments)
        all_pkts += gen_ip_fragments(total_fragments=50)
        wrpcap(args.fragments, all_pkts)
        all_pkts = []

    if args.dns_spoof:
        print("Generating DNS-spoof-like ->", args.dns_spoof)
        all_pkts += gen_dns_spoof_like(count=args.count//100)
        wrpcap(args.dns_spoof, all_pkts)
        all_pkts = []

    print("Done.")
    
if __name__ == "__main__":
    main()
