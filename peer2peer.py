import socket
import struct 
import threading 
import hashlib
import random
import time
import sys
import os

from collections import deque 
from queue import Queue

# Configuração da rede (corrigido o nome da constante)
LISTEN_PORT = 51511
MAX_CHAT_LENGTH = 255  # Nome corrigido
HASH_SIZE = 16
VERIFIER_SIZE = 16
MAX_CHAT_HISTORY = 1000

# Constantes de tipo da mensagem
PEER_REQUEST = 0x1
PEER_LIST = 0x2
ARCHIVE_REQUEST = 0x3
ARCHIVE_RESPONSE = 0x4

# Configuração de rede
PEER_UPDATE_INTERVAL = 5
CONNECTION_TIMEOUT = 10
MINING_THREADS = 4

# Constantes de verificação
MD5_ZERO_PREFIX = b'\x00\x00'
MINING_BATCH_SIZE = 1000


def recv_exact(sock, n):
   	#Le exatamente n bytes do socket
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError(f"Conexão encerrada enquanto aguardava {n} bytes")
        data += packet
    return data

class Block:
    # Construtor
    def __init__(self, text, nonce=None, md5=None):  # Corrigido
        if len(text) > MAX_CHAT_LENGTH:
            raise ValueError(f"Chat muito longo (max {MAX_CHAT_LENGTH} caracteres)")
        
        self.text = text
        self.nonce = nonce if nonce else os.urandom(VERIFIER_SIZE)
        self.md5 = md5

    #tranforma os dados em binario
    def serialize(self):
        text_bytes = self.text.encode('ascii')
        return (
            struct.pack('B', len(text_bytes)) + 
            text_bytes + 
            self.nonce + 
            (self.md5 if self.md5 else bytes(HASH_SIZE))
        )

    @classmethod
    def deserialize(cls, data):
        if len(data) < 1:
            raise ValueError("Dados insuficientes para deserialização")
        
        text_len = struct.unpack('B', data[0:1])[0]
        if len(data) < 1 + text_len + VERIFIER_SIZE + HASH_SIZE:
            raise ValueError("Dados incompletos para deserialização")
        
        text = data[1:1+text_len].decode('ascii')
        nonce = data[1+text_len:1+text_len+VERIFIER_SIZE]
        md5 = data[1+text_len+VERIFIER_SIZE:1+text_len+VERIFIER_SIZE+HASH_SIZE]
        
        return cls(text, nonce, md5)


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_chats = deque(maxlen=20)
        self.lock = threading.Lock()
    
    def add_block(self, block):
        with self.lock:
            if not self.is_valid_block(block):
                return False
            
            self.chain.append(block)
            self.pending_chats.append(block)
            return True

    def is_valid_block(self, block):
        if not self.chain:
            return True
        
        if block.md5[:2] != MD5_ZERO_PREFIX:
            return False
        
        data = b''
        start_idx = max(0, len(self.chain) - 19)
        
        for blk in self.chain[start_idx:]:
            data += blk.serialize()
        
        text_bytes = block.text.encode('ascii')
        data += struct.pack('B', len(text_bytes))
        data += text_bytes
        data += block.nonce
        
        calculated_md5 = hashlib.md5(data).digest()
        return calculated_md5 == block.md5

    def verify_chain(self):
        if not self.chain:
            return True
        
        temp_chain = self.chain.copy()
        return self._verify_chain_recursive(temp_chain)
    
    def _verify_chain_recursive(self, chain):
        if not chain:
            return True
        
        temp_blockchain = Blockchain()
        for block in chain[:-1]:
            temp_blockchain.add_block(block)
        
        last_block = chain[-1]
        if not temp_blockchain.is_valid_block(last_block):
            return False
        
        return self._verify_chain_recursive(chain[:-1])

    def mine_block(self, text):
        result_queue = Queue()
        threads = []
        
        for _ in range(MINING_THREADS):
            t = threading.Thread(
                target=self._mining_worker,
                args=(text, result_queue)
            )
            t.daemon = True
            t.start()
            threads.append(t)
        
        while True:
            result = result_queue.get()
            if result:
                return result

    def _mining_worker(self, text, result_queue):
        new_block = Block(text)
        
        while not result_queue.empty():
            with self.lock:
                data = b''
                start_idx = max(0, len(self.chain) - 19)
                
                for blk in self.chain[start_idx:]:
                    data += blk.serialize()
                
                text_bytes = text.encode('ascii')
                data += struct.pack('B', len(text_bytes))
                data += text_bytes
            
            for _ in range(MINING_BATCH_SIZE):
                new_block.nonce = os.urandom(VERIFIER_SIZE)
                full_data = data + new_block.nonce
                
                new_md5 = hashlib.md5(full_data).digest()
                if new_md5[:2] == MD5_ZERO_PREFIX:
                    new_block.md5 = new_md5
                    
                    with self.lock:
                        if self.is_valid_block(new_block):
                            result_queue.put(new_block)
                            return
            
            time.sleep(0.01)


class P2PNode:
    def __init__(self, bootstrap_peer=None):
        self.blockchain = Blockchain()
        self.peers = set()
        self.active_connections = {}
        self.lock = threading.Lock()
        self.running = True
        
        if bootstrap_peer:
            self.add_peer(bootstrap_peer)
    
    def add_peer(self, peer_ip):
        with self.lock:
            if peer_ip not in self.peers:
                self.peers.add(peer_ip)
                threading.Thread(
                    target=self.connect_to_peer,
                    args=(peer_ip,),
                    daemon=True
                ).start()
    
    def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind(('0.0.0.0', LISTEN_PORT))
            server.listen(10)
            server.settimeout(1)
            
            while self.running:
                try:
                    client, addr = server.accept()
                    ip = addr[0]
                    
                    with self.lock:
                        if ip not in self.active_connections:
                            self.active_connections[ip] = client
                            threading.Thread(
                                target=self.handle_connection,
                                args=(client, ip),
                                daemon=True
                            ).start()
                        else:
                            client.close()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.running:
                        print(f"Erro no servidor: {e}")
                    break
        finally:
            server.close()
    
    def connect_to_peer(self, peer_ip):
	    try:
	        print(f"[INFO] Conectando a peer: {peer_ip}:{LISTEN_PORT}")
	        sock = socket.create_connection((peer_ip, LISTEN_PORT), timeout=CONNECTION_TIMEOUT)
	        sock.settimeout(CONNECTION_TIMEOUT)

	        with self.lock:
	            self.active_connections[peer_ip] = sock

	        print(f"[OK] Conectado com sucesso a {peer_ip}")
	        self.send_message(sock, PEER_REQUEST)

	        threading.Thread(
	            target=self.handle_connection,
	            args=(sock, peer_ip),
	            daemon=True
	        ).start()
	    except Exception as e:
	        print(f"[ERRO] Falha ao conectar a {peer_ip}: {e}")
	        with self.lock:
	            self.peers.discard(peer_ip)
    
    def handle_connection(self, sock, peer_ip):
        try:
            while self.running:
                msg_type = sock.recv(1)
                if not msg_type:
                    break
                
                msg_type = msg_type[0]
                
                if msg_type == PEER_REQUEST:
                    self.handle_peer_request(sock)
                
                elif msg_type == PEER_LIST:
                    self.handle_peer_list(sock)
                
                elif msg_type == ARCHIVE_REQUEST:
                    self.handle_archive_request(sock)
                
                elif msg_type == ARCHIVE_RESPONSE:
                    self.handle_archive_response(sock)
                
                else:
                    print(f"Tipo de mensagem desconhecido: {msg_type} de {peer_ip}")
                    break
        except socket.timeout:
            print(f"Timeout na conexão com {peer_ip}")
        except ConnectionResetError:
            print(f"Conexão resetada por {peer_ip}")
        except Exception as e:
            print(f"Erro na conexão com {peer_ip}: {e}")
        finally:
            with self.lock:
                if peer_ip in self.active_connections:
                    del self.active_connections[peer_ip]
                self.peers.discard(peer_ip)
            try:
                sock.close()
            except:
                pass
    
    def send_message(self, sock, msg_type, data=b''):
        try:
            sock.sendall(bytes([msg_type]) + data)
        except Exception as e:
            print(f"Erro ao enviar mensagem: {e}")
    
    def handle_peer_request(self, sock):
        with self.lock:
            peer_list = list(self.peers)
            data = struct.pack('!I', len(peer_list))
            
            for peer in peer_list:
                try:
                    data += socket.inet_aton(peer)
                except OSError:
                    continue
            
            self.send_message(sock, PEER_LIST, data)
    
    def handle_peer_list(self, sock):
	    try:
	        data = recv_exact(sock, 4)
	        num_peers = struct.unpack('!I', data)[0]
	        peers_data = recv_exact(sock, 4 * num_peers)

	        for i in range(num_peers):
	            ip_bytes = peers_data[i*4:(i+1)*4]
	            try:
	                peer_ip = socket.inet_ntoa(ip_bytes)
	                if peer_ip not in self.peers:
	                    self.add_peer(peer_ip)
	            except OSError:
	                continue

	    except Exception as e:
	        print(f"Erro ao receber PeerList: {e}")
	        return

    
    def handle_archive_request(self, sock):
        with self.lock:
            data = struct.pack('!I', len(self.blockchain.chain))
            for block in self.blockchain.chain:
                data += block.serialize()
            
            self.send_message(sock, ARCHIVE_RESPONSE, data)
    
    def handle_archive_response(self, sock):
	    try:
	        data = recv_exact(sock, 4)
	        num_blocks = struct.unpack('!I', data)[0]
	        blocks = []

	        for _ in range(num_blocks):
	            text_len_data = recv_exact(sock, 1)
	            text_len = text_len_data[0]
	            block_size = 1 + text_len + VERIFIER_SIZE + HASH_SIZE
	            block_data = text_len_data + recv_exact(sock, block_size - 1)

	            block = Block.deserialize(block_data)
	            blocks.append(block)

	    except Exception as e:
	        print(f"Erro ao receber ArchiveResponse: {e}")
	        return

	    new_blockchain = Blockchain()
	    for block in blocks:
	        if not new_blockchain.add_block(block):
	            print("Bloco inválido recebido")
	            return

	    if new_blockchain.verify_chain() and len(new_blockchain.chain) > len(self.blockchain.chain):
	        print(f"Atualizando blockchain para {len(new_blockchain.chain)} blocos")
	        self.blockchain = new_blockchain

    
    def peer_discovery_loop(self):
        while self.running:
            time.sleep(PEER_UPDATE_INTERVAL)
            
            with self.lock:
                peers_to_remove = []
                active_connections = list(self.active_connections.items())
                
                for ip, sock in active_connections:
                    try:
                        self.send_message(sock, PEER_REQUEST)
                    except:
                        peers_to_remove.append(ip)
                
                for ip in peers_to_remove:
                    if ip in self.active_connections:
                        try:
                            self.active_connections[ip].close()
                        except:
                            pass
                        del self.active_connections[ip]
                    self.peers.discard(ip)
    
    def broadcast_blockchain(self):
        with self.lock:
            data = struct.pack('!I', len(self.blockchain.chain))
            for block in self.blockchain.chain:
                data += block.serialize()
            
            for ip, sock in list(self.active_connections.items()):
                try:
                    self.send_message(sock, ARCHIVE_RESPONSE, data)
                except:
                    try:
                        sock.close()
                    except:
                        pass
                    del self.active_connections[ip]
                    self.peers.discard(ip)
    
    def start(self):
        threading.Thread(target=self.start_server, daemon=True).start()
        threading.Thread(target=self.peer_discovery_loop, daemon=True).start()
        time.sleep(1)
        
        while self.running:
            try:
                message = input("Digite sua mensagem (ou 'exit' para sair): ")
                if not message:
                    continue
                
                if message.lower() == 'exit':
                    self.running = False
                    break
                
                print("Mineração iniciada... (pode levar alguns minutos)")
                start_time = time.time()
                
                new_block = self.blockchain.mine_block(message)
                
                mining_time = time.time() - start_time
                print(f"Bloco minerado em {mining_time:.2f} segundos!")
                print(f"Nonce: {new_block.nonce.hex()}")
                print(f"MD5: {new_block.md5.hex()}")
                
                if self.blockchain.add_block(new_block):
                    print("Bloco adicionado ao blockchain!")
                    self.broadcast_blockchain()
                else:
                    print("Falha ao adicionar bloco (cadeia inválida)")
            
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"Erro: {e}")
        
        with self.lock:
            for sock in self.active_connections.values():
                try:
                    sock.close()
                except:
                    pass
            self.active_connections.clear()
        
        print("Saindo...")

if __name__ == "__main__":
    print("=== Sistema de Chat P2P Blockchain ===")
    print(f"Porta: {LISTEN_PORT}")
    
    bootstrap_ip = input("IP do peer inicial (deixe vazio para ser o primeiro): ").strip()
    
    node = P2PNode(bootstrap_ip if bootstrap_ip else None)
    node.start()


