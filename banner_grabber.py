import socket
from bs4 import BeautifulSoup


def is_web_service(banner):
    # Identificadores de serviço web
    web_identifiers = ['Apache', 'Nginx', 'HTTP', '404', 'Server at']
    return any(web_id in banner for web_id in web_identifiers)


def banner_grab(ip, port):
    try:
        # Estabelece uma conexão TCP
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        # s.send(b'Hello\r\n')
        s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
        banner = s.recv(1024).decode('utf-8', 'ignore')
        s.close()

        if is_web_service(banner):
            for line in banner.split('\n'):
                if line.startswith('Server:'):
                    server_info = line.split('Server: ')[1].strip()
                    return server_info
            return "Serviço Web encontrado, mas informações específicas do servidor não disponíveis."

        return banner
    except Exception as e:
        return f'Falha na obtenção do banner: {e}'
