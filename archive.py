import hashlib
import struct

class Archive:
    def __init__(self):
        # 1 byte fixo (4) + 4 bytes para o contador de mensagens
        self.data = bytearray([4, 0, 0, 0, 0])
        self.chats = []  # Lista de tuplas: (length, message, nonce, hash)
        self.size = 0  # Número de mensagens no arquivo
        self.len = len(self.data)

    def parse_message(self, msg: bytes) -> int:
        count = 0
        for c in msg:
            if c == 10:  # '\n'
                break
            if c < 32 or c > 126:
                return 0
            count += 1
            if count > 255:
                return 0
        return count

    def build_chat_block(self, msg: bytes, nonce: bytes = None, md5: bytes = None) -> bytes:
        block = bytearray([len(msg)]) + msg
        if nonce:
            block += nonce
        if md5:
            block += md5
        return block

    def add_message(self, msg: bytes) -> bool:
        length = self.parse_message(msg)
        if length == 0:
            return False

        msg = msg[:length]
        nonce = 0

        # Prepara S com os últimos 20 blocos (sem o hash do último bloco anterior)
        recent_chats = self.chats[-19:] if len(self.chats) >= 19 else self.chats[:]
        S = bytearray()
        for i, (l, m, n, h) in enumerate(recent_chats):
            if i == len(recent_chats) - 1 and len(recent_chats) > 0:
                # Último bloco anterior, remover hash
                S += self.build_chat_block(m, n)
            else:
                S += self.build_chat_block(m, n, h)

        # Adiciona novo bloco (ainda sem hash)
        S += bytearray([length]) + msg

        # Procura nonce tal que o hash MD5 começa com 00 00
        while True:
            nonce_bytes = nonce.to_bytes(16, byteorder='big')
            candidate = S + nonce_bytes
            md5_hash = hashlib.md5(candidate).digest()
            if md5_hash[:2] == b'\x00\x00':
                break
            nonce += 1

        # Armazena nova mensagem
        self.chats.append((length, msg, nonce_bytes, md5_hash))
        self.data += self.build_chat_block(msg, nonce_bytes, md5_hash)

        # Atualiza contador no cabeçalho
        count = struct.unpack(">I", self.data[1:5])[0] + 1
        self.data[1:5] = struct.pack(">I", count)
        self.size = count
        self.len = len(self.data)

        print(f"\nMensagem adicionada: {msg.decode(errors='replace')}")
        print("Nonce:", nonce_bytes.hex())
        print("MD5:  ", md5_hash.hex())

        return True

    def is_valid(self) -> bool:
        for i in range(1, len(self.chats) + 1):
            if not self._validate(i):
                return False
        return True

    def _validate(self, n: int) -> bool:
        if n == 0:
            return True

        # Prepara sequência S com os últimos 20 (ou menos) chats, exceto o hash do último
        recent_chats = self.chats[max(0, n - 20):n]
        S = bytearray()
        for i, (l, m, nonce, h) in enumerate(recent_chats[:-1]):
            S += self.build_chat_block(m, nonce, h)

        # Último chat (sem o hash)
        last = recent_chats[-1]
        S += self.build_chat_block(last[1], last[2])  # sem MD5

        # Verifica o hash
        computed_md5 = hashlib.md5(S).digest()
        stored_md5 = last[3]

        if stored_md5[:2] != b'\x00\x00':
            print("Hash do último chat não começa com 00 00.")
            return False

        if stored_md5 != computed_md5:
            print("Hash do último chat não corresponde ao MD5 calculado.")
            return False

        return True

    def print_archive(self):
        print("\n----- ARQUIVO -----")
        print(f"Número de mensagens: {len(self.chats)}")
        for i, (l, m, nonce, h) in enumerate(self.chats):
            print(f"[{i}] ({l} bytes): {m.decode(errors='replace')}")
            print("Nonce:", nonce.hex())
            print("MD5:  ", h.hex())
        print("----- FIM -----")
