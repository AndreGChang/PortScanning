from scapy.all import *

def scan_port(ip, porta):
    #Cria um pacote SNY
    #Usa o RandShort para pegar um valor aleatoria para a porta de origem
    src_port = RandShort()


    #Inicia uma conexão TCP com endereço IP especifico, configura a flag "S", de SYN, que e usada para iniciar uma conexão TCP(o primeiro processo do handshake de três vias do TCP).
    p = IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S")

    #envia o pacote e espera pela resposta
    resp = sr1(p, timeout=3, verbose=0)

    # Checa a resposta
    if resp is None:
        print(f"Port {port}: Sem resposta")
    elif resp.haslayer(TCP):
        if resp.getlayer(TCP).flags == 0x12:
            #porta aberta
            print(f"Port {port}: Aberta")
            # Envia um pacote RST para encerrar a conexão
            sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R"), timeout=3, verbose=0)
        elif resp.getlayer(TCP).flags == 0x14:
            # Porta fechada
            print(f"Posta {port}: fechada")
    else:
        print(f"Posta {port}: Resposta inesperada")

#Pedindo o IP alvo para o usuario 
target_ip = input("Digite o endereco de Ip alvo: ")

# Definindo o range de postas

start_port = 1
end_port = 1024

#realiza o scan
for port in range(start_port,end_port + 1):
    scan_port(target_ip, port)