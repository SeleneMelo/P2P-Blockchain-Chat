import socket
import struct 
import threading 
import hashlib
import random
import time
import pickle
import sys
import os

from collections import deque 
from queue import Queue

BLOCKCHAIN_FILE = "blockchain.pkl"  

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
NOTIFICATION_MESSAGE = 0x5 #debug

# Configuração de rede
PEER_UPDATE_INTERVAL = 5
CONNECTION_TIMEOUT = 10
MINING_THREADS = 4

# Constantes de verificação
MD5_ZERO_PREFIX = b'\x00\x00'
MINING_BATCH_SIZE = 1000



def get_all_local_ips():
    ips = set()

    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except:
        pass

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except:
        pass

    # Adiciona loopback
    ips.add("127.0.0.1")

    # Adiciona manualmente seu IP público conhecido
    ips.add("177.212.42.4")

    return ips



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


    def serialize(self):
        text_bytes = self.text.encode('utf-8')
        md5_bytes = self.md5 if self.md5 else bytes(HASH_SIZE)
        return struct.pack('B', len(text_bytes)) + text_bytes + self.nonce + md5_bytes


    @classmethod
    def deserialize(cls, data):
        if len(data) < 1:
            raise ValueError("Dados insuficientes para deserialização")

        text_len = struct.unpack('B', data[0:1])[0]
        if len(data) < 1 + text_len + VERIFIER_SIZE + HASH_SIZE:
            raise ValueError("Dados incompletos para deserialização")

        text = data[1:1+text_len].decode('utf-8', errors="replace")  # ✅ Corrigido
        nonce = data[1+text_len:1+text_len+VERIFIER_SIZE]
        md5 = data[1+text_len+VERIFIER_SIZE:1+text_len+VERIFIER_SIZE+HASH_SIZE]

        return cls(text, nonce, md5)


class Blockchain:
    def __init__(self):
        self.chain = []
        self.pending_chats = deque(maxlen=20)
        self.lock = threading.Lock()
        self.load_from_file()
    
    def add_block(self, block):
        with self.lock:
            if not self.is_valid_block(block):
                return False
            
            self.chain.append(block)
            self.pending_chats.append(block)
            self.save_to_file()  # Salva a blockchain após adicionar o bloco
            return True

    def build_mining_data(self, chain, new_block):
        """
        Constrói a sequência de bytes para mineração ou verificação.
        Usa os últimos 19 blocos + novo bloco (sem MD5).
        """
        data = b''

        last_blocks = chain[-19:] if len(chain) >= 19 else chain[:]
        for blk in last_blocks:
            blk_data = blk.serialize()
            data += blk_data[:-HASH_SIZE]  # remove os últimos 16 bytes (MD5)

        text_bytes = new_block.text.encode('utf-8')
        data += struct.pack('B', len(text_bytes))
        data += text_bytes
        data += new_block.nonce

        return data


    def is_valid_block(self, block):
        if not block or not block.md5 or len(block.md5) != HASH_SIZE:
            return False

        if block.md5[:2] != MD5_ZERO_PREFIX:
            return False

        try:
            data = self.build_mining_data(self.chain, block)
            calculated_md5 = hashlib.md5(data).digest()
            return calculated_md5 == block.md5
        except Exception as e:
            print(f"[ERRO] na validação do bloco: {e}")
            return False


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
        return temp_blockchain.is_valid_block(last_block) and temp_blockchain._verify_chain_recursive(chain[:-1])


    def mine_block(self, text):
        result_queue = Queue()
        threads = []
        stop_event = threading.Event()

        for _ in range(MINING_THREADS):
            t = threading.Thread(
                target=self._mining_worker,
                args=(text, result_queue, stop_event)
            )
            t.daemon = True
            t.start()
            threads.append(t)

        block = result_queue.get()
        stop_event.set()  # sinaliza para todos os threads pararem
        return block


    def _mining_worker(self, text, result_queue, stop_event):
        new_block = Block(text)
        attempts = 0

        while not stop_event.is_set():
            for _ in range(MINING_BATCH_SIZE):
                if stop_event.is_set():
                    return

                new_block.nonce = os.urandom(VERIFIER_SIZE)

                with self.lock:
                    data = self.build_mining_data(self.chain, new_block)

                new_md5 = hashlib.md5(data).digest()

                if new_md5.startswith(MD5_ZERO_PREFIX):
                    new_block.md5 = new_md5

                    # Verifica se o bloco é válido com a blockchain atual
                    with self.lock:
                        if self.is_valid_block(new_block):
                            print(f"[✔] Bloco minerado após {attempts} tentativas")
                            result_queue.put(new_block)
                            return

                attempts += 1
                if attempts % 10000 == 0:
                    print(f"[miner] Tentativas até agora: {attempts}")

            time.sleep(0.01)



    def save_to_file(self):
        try:
            with open(BLOCKCHAIN_FILE, "wb") as f:
                pickle.dump(self.chain, f)
        except Exception as e:
            print(f"[ERRO] Falha ao salvar blockchain: {e}")

    def load_from_file(self):
        try:
            with open(BLOCKCHAIN_FILE, "rb") as f:
                self.chain = pickle.load(f)
                for block in self.chain:
                    self.pending_chats.append(block)
            print(f"[LOAD] Blockchain carregada com {len(self.chain)} blocos")
        except FileNotFoundError:
            print("[LOAD] Nenhum arquivo de blockchain existente encontrado")
        except Exception as e:
            print(f"[ERRO] Falha ao carregar blockchain: {e}")


class P2PNode:
    def __init__(self, bootstrap_peer=None):
        self.blockchain = Blockchain()
        self.blockchain.load_from_file()
        self.peer_logs = {}  # mapa: ip → arquivo de log
        self.peers = set()
        self.active_connections = {}
        self.lock = threading.Lock()
        self.running = True
        self.local_ips = get_all_local_ips()



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

                            # Abrir arquivo de log para esse peer
                            fd = client.fileno()
                            log_path = f"{fd}.log"
                            log_file = open(log_path, "a")
                            self.peer_logs[ip] = log_file

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
                # Criação do arquivo de log por peer
                fd = sock.fileno()
                log_path = f"{fd}.log"
                log_file = open(log_path, "a")
                self.peer_logs[peer_ip] = log_file

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
        log = self.peer_logs.get(peer_ip)
        def log_print(msg):
            if log:
                log.write(msg + "\n")
                log.flush()
        try:
            while self.running:
                try:
                    msg_type = recv_exact(sock, 1)[0]
                except socket.timeout:
                    log_print(f"[TIMEOUT] Timeout na conexão com {peer_ip}")
                    break
                except ConnectionError:
                    log_print(f"[DESCONECTADO] Conexão encerrada por {peer_ip}")
                    break

                if msg_type == PEER_REQUEST:
                    self.handle_peer_request(sock)
                    log_print(f"[RECV] PEER_REQUEST de {peer_ip}")

                elif msg_type == PEER_LIST:
                    self.handle_peer_list(sock)
                    log_print(f"[RECV] PEER_LIST de {peer_ip}")

                elif msg_type == ARCHIVE_REQUEST:
                    self.handle_archive_request(sock)
                    log_print(f"[RECV] ARCHIVE_REQUEST de {peer_ip}")

                elif msg_type == ARCHIVE_RESPONSE:
                    self.handle_archive_response(sock)
                    log_print(f"[RECV] ARCHIVE_RESPONSE de {peer_ip}")

                elif msg_type == NOTIFICATION_MESSAGE:
                    try:
                        length = recv_exact(sock, 1)[0]
                        message = recv_exact(sock, length)
                        try:
                            decoded = message.decode('utf-8', errors='replace')
                            #log_print(f"[NOTIF] {decoded}")
                        except UnicodeDecodeError:
                            log_print(f"[NOTIF] Mensagem binária recebida (não decodificável)")
                    except Exception as e:
                        log_print(f"[ERRO] Falha ao receber NOTIFICATION_MESSAGE: {e}")
                
                else:
                    pass

        except ConnectionResetError:
            log_print(f"[RESET] Conexão resetada por {peer_ip}")
        except Exception as e:
            log_print(f"[ERRO] Erro na conexão com {peer_ip}: {e}")
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
                    
                    if peer_ip in self.local_ips:
                        #print(f"[IGNORADO] IP local ignorado na PeerList: {peer_ip}")
                        continue

                    if peer_ip not in self.peers:
                        self.add_peer(peer_ip)

                except OSError:
                    continue

        except Exception as e:
            print(f"Erro ao receber PeerList: {e}")
            return

    
    def handle_archive_response(self, sock):
        peer_ip = None
        for ip, s in self.active_connections.items():
            if s == sock:
                peer_ip = ip
                break

        log = self.peer_logs.get(peer_ip)

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

                if log:
                    log.write(f"[RECV BLOCK] {block.text}\n")
                    log.write(f"             Nonce: {block.nonce.hex()}\n")
                    log.write(f"             MD5:   {block.md5.hex()}\n")
                    log.flush()

        except Exception as e:
            if log:
                log.write(f"[ERRO] Falha ao processar ArchiveResponse: {e}\n")
                log.flush()
            return

        new_blockchain = Blockchain()
        for block in blocks:
            if not new_blockchain.add_block(block):
                if log:
                    log.write("[ERRO] Bloco inválido recebido - ignorando blockchain\n")
                    log.flush()
                return

        if new_blockchain.verify_chain():
            if len(new_blockchain.chain) > len(self.blockchain.chain):
                self.blockchain = new_blockchain
                if log:
                    log.write(f"[ATUALIZAÇÃO] Blockchain atualizada para {len(new_blockchain.chain)} blocos\n")
                    log.flush()
            else:
                if log:
                    log.write("[INFO] Blockchain recebida é menor ou igual — ignorada\n")
                    log.flush()

    def handle_archive_request(self, sock):
        with self.lock:
            data = struct.pack('!I', len(self.blockchain.chain))
            for block in self.blockchain.chain:
                data += block.serialize()

            self.send_message(sock, ARCHIVE_RESPONSE, data)

            peer_ip = None
            for ip, s in self.active_connections.items():
                if s == sock:
                    peer_ip = ip
                    break

            log = self.peer_logs.get(peer_ip)
            if log:
                log.write("[SEND ARCHIVE_RESPONSE] Enviando blockchain com %d blocos\n" % len(self.blockchain.chain))
                log.flush()
        

    
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
                    print(f"[BROADCAST] Enviando blockchain com {len(self.blockchain.chain)} blocos para {ip}")
                    self.send_message(sock, ARCHIVE_RESPONSE, data)

                    log = self.peer_logs.get(ip)
                    if log:
                        log.write("[SEND ARCHIVE_RESPONSE] Enviando blockchain com %d blocos\n" % len(self.blockchain.chain))
                        log.flush()
                        time.sleep(5)
                except:
                    try:
                        sock.close()
                    except:
                        pass
                    del self.active_connections[ip]
                    self.peers.discard(ip)

        # Adicione este método à classe P2PNode
    def cleanup_connections(self):
        with self.lock:
            to_remove = []
            for ip, sock in self.active_connections.items():
                try:
                    # Testa se a conexão ainda está ativa
                    sock.send(b'')  # Pacote vazio apenas para testar
                except:
                    to_remove.append(ip)
            
            for ip in to_remove:
                try:
                    self.active_connections[ip].close()
                except:
                    pass
                del self.active_connections[ip]
                self.peers.discard(ip)
                if ip in self.peer_logs:
                    try:
                        self.peer_logs[ip].close()
                    except:
                        pass
                    del self.peer_logs[ip]

    def connection_cleanup_loop(self):
        while self.running:
            time.sleep(30)  # A cada 30 segundos
            self.cleanup_connections()
    
    def start(self):
        threading.Thread(target=self.start_server, daemon=True).start()
        threading.Thread(target=self.peer_discovery_loop, daemon=True).start()
        threading.Thread(target=self.connection_cleanup_loop, daemon=True).start()
        time.sleep(1)

        with self.lock:
            for ip, sock in self.active_connections.items():
                try:
                    print(f"[SYNC] Solicitando blockchain de {ip}")
                    self.send_message(sock, ARCHIVE_REQUEST)
                except:
                    continue

        print("[SYNC] Aguardando resposta de blockchain do servidor...")
        time.sleep(3)

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

                    for ip, log in self.peer_logs.items():
                        try:
                            log.write(f"[BROADCAST] Novo bloco minerado: '{new_block.text}'\n")
                            log.write(f"          Nonce: {new_block.nonce.hex()}\n")
                            log.write(f"          MD5:   {new_block.md5.hex()}\n")
                            log.flush()
                        except:
                            continue

                    time.sleep(1.5)  # Aguarda o servidor enviar ARCHIVE_REQUEST
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



