import socket
import sys
from scan import *
from banner_grabber import banner_grab

def is_valid_ip(target_ip):
    try:
        socket.inet_aton(target_ip)
        return True
    except socket.error:
        return False
    
def get_ip_from_input(input_str):
    if is_valid_ip(input_str):
        return input_str
    else:
        try:
            ip = socket.gethostbyname(input_str)
            return ip
        except socket.gaierror:
            return None
        
if len(sys.argv) != 3:
    print("Uso: python index.py <alvo> <tipo>")
    print("Exemplo: python index.py 192.168.1.1 tcp")
    sys.exit(1)

target = get_ip_from_input(sys.argv[1])
print(target)
if target is None:
    print("Endereço invalido ou nome de host não resolvido")
    sys.exit(1)

scan_type = sys.argv[2].lower()
start_port = 1
end_port = 1000


if scan_type == "udp":
        print(f"Iniciando varredura UDP em {target}")
        for port in range(start_port, end_port + 1):
            scan_udp(target, port)
        print("Varredura UDP concluída.")
elif scan_type == "tcp":
        print(f"Iniciando varredura TCP em {target}")
        for port in range(start_port, end_port + 1):
            scan_syn(target, port)
        print("Varredura TCP concluída.")
else:
    print("Tipo de varredura inválido. Use 'tcp' ou 'udp'.")
