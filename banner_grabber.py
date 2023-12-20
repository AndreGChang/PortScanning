import socket

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