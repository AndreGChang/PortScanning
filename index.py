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

if len(sys.argv) != 4:
    print("Uso: python index.py <alvo> <tipo> <porta_inicial> <porta_final>")
    print("Exemplo: python scanner.py 192.168.1.1 tcp 1 1024")
    sys.exit(1)

target = sys.argv[1]
scan_type = sys.argv[2].lower()
start_port = int(sys.argv[3])
end_port = int(sys.argv[4])

# Obtenha o endereço IP associado ao domínio ou use o endereço IP diretamente
ip = get_ip_from_input(target)


if ip:
    if scan_type == "udp":
        for port in range(start_port, end_port + 1):
            if scan_udp_port(target, port):
              banner = banner_grab(target, port)
              print(f"A porta UDP: {port} esta aberta, Banner: {banner}")

    elif scan_type == "tcp":
        for port in range(start_port, end_port + 1):
            if scan_port(target_ip, port):
                banner = banner_grab(target_ip, port)
                print(f"Porta {port}: Aberta, Banner: {banner}")
else:
    print(f"Não foi possível obter o endereço IP para {target_ip}. Certifique-se de que seja um domínio válido ou um endereço IP válido.")

