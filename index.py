from scapy.all import *
import socket

def scan_port(ip, port):
    src_port = RandShort()
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")
    resp = sr1(p, timeout=2, verbose=0)

    if resp is not None and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        return True  # Porta aberta
    return False

def banner_grab(ip, port):
    try:
        # Estabelece uma conexão TCP
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))
        s.send(b'Hello\r\n')
        banner = s.recv(1024)
        s.close()
        return banner.decode('utf-8', 'ignore')
    except: 
        return 'Falha na obtenção do banner'

# Definindo o range de portas
start_port = 1
end_port = 1024  # Ajuste conforme necessário

# Pedindo ao usuário para inserir o IP alvo 
target_ip = input("Digite o endereço IP alvo: ")

# Realizando o scan
for port in range(start_port, end_port + 1):
    if scan_port(target_ip, port):
        banner = banner_grab(target_ip, port)
        print(f"Porta {port}: Aberta, Banner: {banner}")
