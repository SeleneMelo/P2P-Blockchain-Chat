import socket
import struct
import fcntl
import errno

TCP_PORT = 51511

# Definições dos tipos de mensagem usados na comunicação
MSG_PEERREQ = 1
MSG_PEERLIST = 2
MSG_ARCHREQ = 3
MSG_ARCHRESP = 4


def init_peer_socket(ip):
    try:
        # Cria socket TCP não bloqueante para conexão com peer
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)

        try:
            sock.connect((ip, TCP_PORT))  # Inicia conexão
        except BlockingIOError:
            pass  # Conexão ainda em andamento (não bloqueante)

        # Aguarda até 0.5s para verificar se socket está pronto para escrita
        import select
        ready = select.select([], [sock], [], 0.5)
        if ready[1]:
            # Verifica erro na conexão
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 0:
                sock.setblocking(True)  # Volta para modo bloqueante
                return sock
            else:
                sock.close()
                return -1
        else:
            sock.close()
            return -1

    except Exception as e:
        print(f"init_peer_socket() error: {e}")
        return -1


def init_incoming_socket():
    try:
        # Cria socket TCP para aceitar conexões de peers
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permite reutilizar endereço
        sock.bind(('', TCP_PORT))  # Escuta em todas interfaces no TCP_PORT
        return sock
    except Exception as e:
        print(f"init_incoming_socket() error: {e}")
        return -1
