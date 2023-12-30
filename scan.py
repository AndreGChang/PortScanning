import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from banner_grabber import banner_grab

time_max_await = 5

def scan_tcp(ip, port):
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return f"Porta: {port} filtrada" # Sem resposta, possivelmente filtrada
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            banner = banner_grab(ip, port)
            sr(IP(dst=ip)/TCP(dport=resp.sport, flags='R'), timeout=time_max_await, verbose=0)
            return f"Porta: {port} Aberta - Serviço: {banner}"
        elif resp.getlayer(TCP).flags == 0x14:
            return f"Porta: {port} Fechada"
    return f"Porta: {port} Estado Desconhecido"

def scan_udp(ip,port):
    src_port = RandShort()
    p = IP(dst=ip)/UDP(sport=src_port, dport=port)
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return f"Porta: {port} UDP - Aberta?filtrada"
    elif resp.haslayer(ICMP):
        return f"Porta: {port} UDP - Fechada/Filtrada"
    return f"Porta: {port} UDP - Estado Desconhecido"
