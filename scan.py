from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

def scan_port(ip, port):
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(p, timeout=2, verbose=0)

    if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        sr(IP(dst=ip)/TCP(dport=ip.sport, flag='R'), timeout=1, verbose=0)
        return True  # Porta aberta
    return False


def scan_udp_port(ip,port):
    src_port = RandShort()
    p = IP(dst=ip)/UDP(sport=src_port, dport=port)
    resp = sr1(p, timeout=2, verbose=0)

    if resp is not None and resp.haslayer(UDP):
        return True # Prota UDP aberta
    return False
