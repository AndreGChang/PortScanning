import socket
import argparse
from scan import *
from banner_grabber import banner_grab

class ScanManager:
    def __init__(self):
        # self.colocar classe de scan
        self.parse_args()
        
    def parse_args(self):
        parser = argparse.ArgumentParser(description="Ferramenta de Varredura de Rede")
        parser.add_argument("target", help="Endereço IP ou hostname do alvo")
        parser.add_argument("scan_type", help="Tipo de Varredura (sT,sU,sF,sX,sN,sFA,sA,sTW)", default="sT")
        parser.add_argument("-p", "--ports", nargs='+', type=int, help="Lista de portas para varrer", default=range(1, 1026))
        self.args = parser.parse_args()

    
    def is_valid_ip(self, target_ip):
        try:
            socket.inet_aton(target_ip)
            return True
        except socket.error:
            return False


    def get_ip_from_input(self, input_str):
        if self.is_valid_ip(input_str):
            return input_str
        else:
            try:
                ip = socket.gethostbyname(input_str)
                return ip
            except socket.gaierror:
                return None
            
    def run_scan(self):
        target_ip = self.get_ip_from_input(self.args.target)
        if target_ip is None:
            print("Endereço invalido ou nome de host não resolvido")
            sys.exit(1)

    if args.scan_type == "sU":
        print(f"Iniciando varredura UDP em {target}")
        for port in ports:
            result = scan_udp(target, port)
            if result == True:
                banner = banner_grab(target, port)
                print(f"Porta {port} aberta/filtrada - serviço {banner}")
        print("Varredura UDP concluída.")

elif scan_type == "sS":
    print(f"Iniciando varredura TCP em {target}")
    for port in ports:
        result = scan_syn(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - serviço {banner}")
    print("Varredura TCP concluída.")

elif scan_type == "sF":
    print(f"Iniciando varredura TCP FIN em {target}")
    for port in ports:
        result = scan_fin(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - seviço {banner}")
    print("Varredura TCP FIN concluída.")

elif scan_type == "sX":
    print(f"Iniciando varredura TCP XMAS em {target}")
    for port in ports:
        result = scan_xmas(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} Aberta - serviço {banner}")
        elif result == False:
            print(f"Porta {port} filtrada")
    print("Varredura XMAS concluída.")

elif scan_type == "sN":
    print(f"Iniciando varredura TCP NULL em {target}")
    for port in ports:
        result = scan_null(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - serviço {banner}")
        elif result == False:
            print("porta {port} filtrada")
    print("Varredura TCP NULL concluída.")

elif scan_type == "sFA":
    print(f"Iniciando varredura TCP FIN/ACK em {target}")
    for port in ports:
        result = scan_fin_ack(target, port)
        if result == True:
            banner = banner_grab(target, port)
            print(f"Porta {port} aberta - service {banner}")
        elif result == False:
            print(f"Porta {port} fechada/filtrada")
    print("Varredura TCP FIN/ACK concluída.")

elif scan_type == "sA":
    print(f"Iniciando varredura TCP ACK em {target}")
    for port in ports:
        scan_ack(target, port)
    print("Varredura TCP ACK concluída.")

elif scan_type == "sTW":
    print(f"Iniciando varredura TCP Windown em {target}")
    for port in ports:
        scan_tcp_windown(target, port)
    print("Varredura TCP Windown concluída.")
