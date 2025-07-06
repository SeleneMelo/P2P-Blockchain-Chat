from typing import Optional
import struct
import sys


class Node:
    def __init__(self, ip: int, sock: int):
        self.ip = ip
        self.sock = sock
        self.next: Optional['Node'] = None  # Próximo nó na lista encadeada


class PeerList:
    def __init__(self):
        self.head = Node(0, 0)  # Nó cabeça fictício
        self.last = self.head   # Último nó da lista
        self.size = 0
        # Representação da lista como bytes: tipo=2 + tamanho=0 (4 bytes)
        self.str = bytearray(5)
        self.str[0] = 2
        self.str[1:5] = (0).to_bytes(4, byteorder='big')

    def list_to_str(self):
        # Atualiza self.str para refletir a lista atual de peers
        buf = bytearray(5 + self.size * 4)
        buf[0] = 2
        buf[1:5] = self.size.to_bytes(4, byteorder='big')

        aux = self.head.next
        offset = 5

        while aux is not None:
            ip_bytes = aux.ip.to_bytes(4, byteorder='little')
            buf[offset:offset+4] = ip_bytes[::-1]  # Converte para big endian (como em C)
            offset += 4
            aux = aux.next

        self.str = buf

    def add_peer(self, ip: int, sock: int):
        # Adiciona novo peer no final da lista e atualiza a string
        new_node = Node(ip, sock)
        self.last.next = new_node
        self.last = new_node
        self.size += 1
        self.list_to_str()

    def remove_peer(self, ip: int):
        # Remove peer da lista pelo IP, se existir
        prev = self.head
        while prev.next is not None:
            if prev.next.ip == ip:
                break
            prev = prev.next

        if prev.next is None:
            return  # IP não encontrado

        to_remove = prev.next
        prev.next = to_remove.next

        if to_remove == self.last:
            self.last = prev

        self.size -= 1
        self.list_to_str()

    def is_connected(self, ip: int) -> bool:
        # Verifica se IP está na lista
        aux = self.head
        while aux is not None:
            if aux.ip == ip:
                return True
            aux = aux.next
        return False

    def print_list(self):
        # Imprime a lista de peers para debug no stderr
        print(f"Peer list [size {self.size}]:", file=sys.stderr)

        if self.head == self.last:
            return

        aux = self.head.next
        while aux != self.last:
            print(f"{aux.ip}[{aux.sock}] -> ", end='', file=sys.stderr)
            aux = aux.next

        print(f"{aux.ip}[{aux.sock}]", file=sys.stderr)
