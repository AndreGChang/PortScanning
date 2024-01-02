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
    print("Exemplo: python index.py 192.168.1.1 sT")
    sys.exit(1)

target = get_ip_from_input(sys.argv[1])
print(target)
if target is None:
    print("Endereço invalido ou nome de host não resolvido")
    sys.exit(1)

scan_type = sys.argv[2]
start_port = 1
end_port = 1000


if scan_type == "sU":
    print(f"Iniciando varredura UDP em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_udp(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta/filtrada - serviço {banner}")
    print("Varredura UDP concluída.")

elif scan_type == "sT":
    print(f"Iniciando varredura TCP em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_syn(target, port)
        if result == True:
           banner = banner_grab(target, port)
           print(f"Porta {port} aberta - serviço {banner}")
    print("Varredura TCP concluída.")

elif scan_type == "sF":
    print(f"Iniciando varredura TCP FIN em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_fin(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - seviço {banner}")
        
    print("Varredura TCP FIN concluída.")

elif scan_type == "sX":
    print(f"Iniciando varredura TCP XMAS em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_xmas(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} Aberta - serviço {banner}")
        elif result == False:
            print(f"Porta {port} filtrada")
    print("Varredura XMAS concluída.")

elif scan_type == "sN":
    print(f"Iniciando varredura TCP NULL em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_null(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - serviço {banner}")
        elif result == False:
            print("porta {port} filtrada")
    print("Varredura TCP NULL concluída.")

elif scan_type == "sFA":
    print(f"Iniciando varredura TCP FIN/ACK em {target}")
    for port in range(start_port, end_port + 1):
        result = scan_fin_ack(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - service {banner}")
        elif result == False:
            print(f"Porta {port} fechada/filtrada")
    print("Varredura TCP FIN/ACK concluída.")

elif scan_type == "sA":
    print(f"Iniciando varredura TCP ACK em {target}")
    for port in range(start_port, end_port + 1):
        scan_ack(target, port)
    print("Varredura TCP ACK concluída.")

elif scan_type == "sTW":
    print(f"Iniciando varredura TCP Windown em {target}")
    for port in range(start_port, end_port + 1):
        scan_tcp_windown(target, port)
    print("Varredura TCP Windown concluída.")

else:
    print("Tipo de varredura inválido. Use 'sT' scan TCP, 'sU' scan UDP, 'sF' scan FIN, 'sX' scan XMAS, 'sN' scan NULL, 'sFA' scan FIN/ACK, 'sA' scan ACK, 'sTW' scan TCP Window.")
