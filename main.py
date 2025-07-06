import sys
import socket
import struct
import threading
import time
import queue

from peerlist import PeerList
from archive import Archive
from protocol import (
    init_peer_socket, init_incoming_socket,
    MSG_PEERREQ, MSG_PEERLIST, MSG_ARCHREQ, MSG_ARCHRESP
)


peerlist = PeerList()
peerlist_mutex = threading.Lock()  # Mutex para acessar a lista de peers
active_arch = Archive()
archive_lock = threading.RLock()  # Lock para proteger o arquivo ativo
myaddr = 0

status_queue = queue.Queue()  # Fila para mensagens de status das threads para o main


def process_peerlist(peersock, logfile):
    data = peersock.recv(4)
    if len(data) < 4:
        return
    size = struct.unpack('!I', data)[0]  # Número de peers na lista
    logfile.write(f"\n----------Processing peer list!----------\n")
    logfile.write(f"{size} clients:\n")

    for _ in range(size):
        data = peersock.recv(4)
        uip = struct.unpack('!I', data)[0] 
        logfile.write(f"{data[0]}.{data[1]}.{data[2]}.{data[3]}\n")

        if uip == myaddr:
            continue  # Ignora a si mesmo

        with peerlist_mutex:
            if not peerlist.is_connected(uip):
                ip_str = socket.inet_ntoa(data)
                print(f"Attempting to connect to new peer {ip_str}... ")
                newpeersock = init_peer_socket(ip_str)
                if newpeersock == -1:
                    print(f"Failed to connect to peer {ip_str}!")
                    continue

                # Cria threads para comunicação com o novo peer
                threading.Thread(target=peer_requester_thread, args=(newpeersock,), daemon=True).start()
                threading.Thread(target=peer_receiver_thread, args=(newpeersock,), daemon=True).start()

    logfile.write("----------Done processing peerlist!----------\n\n")


def process_archive(peersock, logfile):
    logfile.write("\n----------Processing ArchiveResponse!---------\n")
    data = peersock.recv(4)
    usize = struct.unpack('!I', data)[0]  # Quantidade de mensagens no arquivo
    logfile.write(f"Number of chats: {usize}\n")

    new_arch = Archive()
    new_arch.size = usize
    buf = bytearray(5 + usize * 289)  # Buffer para armazenar o arquivo recebido
    ptr = 0
    buf[ptr] = 4  # Código do tipo de mensagem?
    ptr += 1
    buf[ptr:ptr+4] = data
    ptr += 4

    for _ in range(usize):
        msglen = peersock.recv(1)[0]
        msg = peersock.recv(msglen)
        codes = peersock.recv(32)
        buf[ptr] = msglen
        ptr += 1
        buf[ptr:ptr+msglen] = msg
        ptr += msglen
        buf[ptr:ptr+32] = codes
        ptr += 32

    buf = buf[:ptr]
    new_arch.data = buf
    new_arch.len = len(buf)

    logfile.write("Content of archive received:\n")
    new_arch.print_archive()

    with archive_lock:
        if new_arch.size > active_arch.size and new_arch.is_valid():
            active_arch.data = new_arch.data
            active_arch.size = new_arch.size
            active_arch.len = new_arch.len
            print("---------- Active archive replaced! ----------")
        else:
            # Descartar new_arch se inválido ou menor
            pass

    logfile.write("----------Done processing ArchiveResponse!----------\n\n")


def publish_archive():
    print("\n----------Publishing new archive!----------")
    aux = peerlist.head.next
    while aux:
        print(f"Sending to peer at sock {aux.sock}")
        try:
            aux.sock.sendall(active_arch.data)  # Envia arquivo ativo para todos peers
        except:
            pass
        aux = aux.next
    print("----------Done publishing!---------\n")


def peer_requester_thread(peersock):
    logfile = open(f"{peersock}.log", "a")
    msg = bytearray(2)
    msg[0] = MSG_PEERREQ
    msg[1] = MSG_ARCHREQ
    count = 0

    while True:
        try:
            peersock.sendall(msg[:1])  # Envia pedido de peers
        except:
            logfile.write("Error sending peer request, broken pipe?\nTerminating requester thread.\n")
            return
        count += 1

        if count == 12:
            try:
                peersock.sendall(msg[1:2])  # A cada 12, pede o arquivo
            except:
                logfile.write("Error sending archive request, broken pipe?\nTerminating requester thread.\n")
                return
            count = 0

        time.sleep(5)


def peer_receiver_thread(peersock):
    logfile = open(f"{peersock}.log", "a")
    peeraddr = peersock.getpeername()
    upeerip = struct.unpack('<I', socket.inet_aton(peeraddr[0]))[0]
    cpeerip = peeraddr[0]

    with peerlist_mutex:
        peerlist.add_peer(upeerip, peersock)
        status_queue.put(f"Successfully connected to peer {cpeerip}")

    peersock.settimeout(60)  # Timeout para desconexão automática

    while True:
        try:
            typeb = peersock.recv(1)
            if not typeb:
                raise socket.timeout
            typ = typeb[0]
        except:
            print(f"Timed out when waiting for peer {cpeerip}.\nPeer likely disconnected. Closing connection...")
            peersock.close()
            with peerlist_mutex:
                peerlist.remove_peer(upeerip)
            return

        # Processa mensagens recebidas conforme tipo
        if typ == MSG_PEERREQ:
            logfile.write("Received PeerRequest, sending list!\n")
            if peerlist.str is not None:
                peersock.sendall(peerlist.str)
        elif typ == MSG_PEERLIST:
            process_peerlist(peersock, logfile)
        elif typ == MSG_ARCHREQ:
            logfile.write("Received ArchiveRequest!\n")
            if active_arch.size:
                logfile.write("Sending archive!\n")
                peersock.sendall(active_arch.data)
        elif typ == MSG_ARCHRESP:
            process_archive(peersock, logfile)
        else:
            logfile.write(f"Unknown msg type, ignoring... (byte = {typ})\n")


def incoming_peers_thread():
    mysock = init_incoming_socket()
    if mysock == -1:
        return
    mysock.listen(10)
    print("[Incoming peers thread is awaiting connections]")

    while True:
        try:
            peersock, _ = mysock.accept()  # Aceita conexões de peers
        except:
            print("Error, could not accept connection from peer!")
            continue

        print("Accepted incoming peer connection!")
        threading.Thread(target=peer_requester_thread, args=(peersock,), daemon=True).start()
        threading.Thread(target=peer_receiver_thread, args=(peersock,), daemon=True).start()


def main():
    global myaddr
    if len(sys.argv) != 3:
        print("Usage: python main.py <peer_ip> <public_ip>")
        return

    myaddr = struct.unpack('<I', socket.inet_aton(sys.argv[2]))[0]

    threading.Thread(target=incoming_peers_thread, daemon=True).start()

    sock = init_peer_socket(sys.argv[1])
    if sock == -1:
        print("Failed to connect to initial peer!")
    else:
        threading.Thread(target=peer_requester_thread, args=(sock,), daemon=True).start()
        threading.Thread(target=peer_receiver_thread, args=(sock,), daemon=True).start()

    while True:
        # Exibe mensagens de status das threads
        while not status_queue.empty():
            print(status_queue.get())

        msg = input("Input a chat message to send (255 chars max):\n") + '\n'
        with archive_lock:
            if msg == "exit\n":
                sys.exit(0)

            if not active_arch.add_message(msg.encode()):
                print("Invalid message! Try again :)")
                continue

            print("Message successfully added to archive!")
            active_arch.print_archive()
            publish_archive()


if __name__ == "__main__":
    main()
