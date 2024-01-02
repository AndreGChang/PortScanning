import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from banner_grabber import banner_grab

time_max_await = 2

def scan_syn(ip, port):
    # Gera um numero aleatorio para a porta de origem
    src_port = RandShort()
    #Criamos o pacote IP e TCP com o IP de destinho.
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
    # Esperamos a resposta do pacote enviado
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return False
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            sr(IP(dst=ip)/TCP(dport=resp.sport, flags='R'), timeout=time_max_await, verbose=0)
            return True

def scan_udp(ip,port):
    src_port = RandShort()
    p = IP(dst=ip)/UDP(sport=src_port, dport=port)
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return True
    else:
        if resp.haslayer(ICMP):
            return False
        elif resp.hasLayer(UDP):
            return True

def scan_fin(ip,port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags = "F")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return True

def scan_xmas(ip, port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags="FPU")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return True
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return False
    
def scan_null(ip, port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags='')
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return True
    elif resp.haslayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return False
    
def scan_fin_ack(ip, port):
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport = src_port, dport=port, flags="FA")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return True
    elif resp.haslayer(ICMP):
        icmp_type = resp.getlayer(ICMP).type
        if icmp_type == 3:
            return False

def scan_ack(ip, port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags="A")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp in None:
        return False
    elif resp.haslayer(TCP):
       if resp.getlayer(TCP).flags == 0x14:
            return True
    elif resp.hasLayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return True
        
def scan_tcp_windown(ip, port):
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport = src_port, dport = port, flags="A")
    resp = sr1(p, timeout=time_max_await, verbose =0)

    if resp is not None and resp.haslayer(TCP):
        window_size = resp.getlayer(TCP).window_size
        if window_size > 0:
            return f"Porta {port} aberta"
        

