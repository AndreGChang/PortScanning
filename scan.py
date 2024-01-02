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
    else:
        if resp.haslayer(ICMP):
            return f"Porta: {port} UDP - Fechada"
        elif resp.hasLayer(UDP):
            return f"Porta: {port} UDP - Aberta?filtrada"
        else:
            return f"Porta: {port} Desconhecido"

def scan_fin(ip,port):
    src_port = RandShort()
    p = IP(dsp = ip)/TCP(sport=src_port, dport=port, flags = "F")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return f"Porta {port} esta aberta"

def scan_xmas(ip, port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags="FPU")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp is None:
        return f"Porta {port} esta aberta ou filtrada"
    
def scan_null(ip, port):
    src_port = RandShort()
    p = IP(dst = ip)/TCP(sport=src_port, dport=port, flags='')
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp in None:
            return f"Porta {port} aberta"
    
def scan_ack(ip, port):
    src_port = RandShort()
    p = IP(dest = ip)/TCP(sport=src_port, dport=port, flags="A")
    resp = sr1(p, timeout=time_max_await, verbose=0)

    if resp in None:
        return f"A resposta da porta {port} foi filtrada"
    elif resp.haslayer(TCP):
       if resp.getlayer(TCP).flags == 0x14:
            return f"A porta {port} nao esta filtrada"
    elif resp.hasLayer(ICMP):
        if int(resp.getlayer(ICMP).type) == 3 and int(response.getLayer(ICMP).code) in [1,2,3,9,10,13]:
            return f"A porta {port} esta filtrada"