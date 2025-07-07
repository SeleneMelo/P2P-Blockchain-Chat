#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/md5.h>
#include <pthread.h>

#define MSG_PEERREQ  0x1
#define MSG_PEERLIST 0x2
#define MSG_ARCHREQ  0x3
#define MSG_ARCHRESP 0x4
#define MSG_NOTIFY   0x5
#define TCP_PORT "51511"

// ------------------------- Peer List Structures ------------------------- //
void process_peerlist(int peersock, FILE* logfile);
void process_archive(int peersock, FILE* logfile);


struct Node {
    uint32_t ip;
    uint32_t sock;
    Node* next;
};

struct PeerList {
    Node* head;
    Node* last;
    uint32_t size;
    uint8_t* str;
};

PeerList* init_list() {
    PeerList* list = new PeerList;
    list->head = new Node{0, 0, nullptr};
    list->last = list->head;
    list->size = 0;
    list->str = nullptr;
    return list;
}

void list_to_str(PeerList* list) {
    free(list->str);
    list->str = (uint8_t*) malloc(5 + list->size * 4);
    list->str[0] = MSG_PEERLIST;
    list->str[1] = (list->size >> 24) & 0xFF;
    list->str[2] = (list->size >> 16) & 0xFF;
    list->str[3] = (list->size >> 8) & 0xFF;
    list->str[4] = list->size & 0xFF;

    Node* aux = list->head->next;
    for (uint32_t i = 0; i < list->size; ++i, aux = aux->next) {
        list->str[5 + 4*i + 3] = (aux->ip >> 24) & 0xFF;
        list->str[5 + 4*i + 2] = (aux->ip >> 16) & 0xFF;
        list->str[5 + 4*i + 1] = (aux->ip >> 8) & 0xFF;
        list->str[5 + 4*i + 0] = aux->ip & 0xFF;
    }
}

void add_peer(PeerList* list, uint32_t ip, uint32_t sock) {
    list->last->next = new Node{ip, sock, nullptr};
    list->last = list->last->next;
    list->size += 1;
    list_to_str(list);
}

void remove_peer(PeerList* list, uint32_t ip) {
    Node* prev = list->head;
    while (prev->next && prev->next->ip != ip)
        prev = prev->next;
    if (!prev->next) return;

    Node* to_remove = prev->next;
    prev->next = to_remove->next;
    if (to_remove == list->last) list->last = prev;
    delete to_remove;
    list->size -= 1;
    list_to_str(list);
}

int is_connected(PeerList* list, uint32_t ip) {
    Node* aux = list->head;
    while (aux) {
        if (aux->ip == ip) return 1;
        aux = aux->next;
    }
    return 0;
}

// ------------------------- Archive Structure ------------------------- //

struct Archive {
    uint8_t* str;
    uint32_t offset;
    uint32_t size;
    uint32_t len;
};

Archive* init_archive() {
    Archive* arch = new Archive;
    arch->str = (uint8_t*) malloc(5);
    arch->str[0] = MSG_ARCHRESP;
    memset(arch->str + 1, 0, 4);
    arch->offset = 5;
    arch->size = 0;
    arch->len = 5;
    return arch;
}

int parse_message(uint8_t* msg) {
    int count = 0;
    while (count < 255 && msg[count] != '\n') {
        if (msg[count] < 32 || msg[count] > 126) return 0;
        count++;
    }
    return count;
}


int add_message(Archive* arch, uint8_t* msg) {
    uint16_t len = parse_message(msg);
    if (len == 0) return 0;

    printf("\nMessage length = %d\nContent: ", len);
    for (int i = 0; i < len; ++i)
        printf("%c", msg[i]);
    printf("\n");

    // Aloca espaço para nova mensagem (len + texto + 16 verif + 16 md5)
    arch->str = (uint8_t*) realloc(arch->str, arch->len + len + 33);
    arch->str[arch->len] = len;
    memcpy(arch->str + arch->len + 1, msg, len);
    uint8_t* code = arch->str + arch->len + len + 1;
    uint8_t* md5 = code + 16;

    // 🛠️ ATUALIZA OFFSET PARA OS ÚLTIMOS 20 CHATS
    if (arch->size >= 20) {
        uint32_t temp_offset = 5; // pula cabeçalho
        for (uint32_t i = 0; i < arch->size - 19; ++i) {
            uint8_t prev_len = arch->str[temp_offset];
            temp_offset += 1 + prev_len + 32;
        }
        arch->offset = temp_offset;
    }

    // Mineração do código verificador
    unsigned long long attempts = 0;
    uint16_t* check = (uint16_t*) md5;
    
    do {
        // Gera um código verificador aleatório
        for (int i = 0; i < 16; i++) {
            code[i] = rand() & 0xFF;
        }
        
        // Calcula o MD5 dos últimos 20 chats (exceto os últimos 16 bytes)
        uint32_t s_len = arch->len - arch->offset + len + 17;
        MD5(arch->str + arch->offset, s_len, md5);
        
        attempts++;
        if (attempts % 100000 == 0) {
            printf("Mining attempt %llu...\n", attempts);
        }
    } while (*check != 0);

    printf("Found valid hash after %llu attempts!\n", attempts);
    printf("code: ");
    for (int i = 0; i < 16; i++) printf("%02x", code[i]);
    printf("\nmd5: ");
    for (int i = 0; i < 16; i++) printf("%02x", md5[i]);
    printf("\n\n");

    arch->size += 1;
    arch->len += len + 33;

    // Atualiza os 4 bytes de tamanho em Big-Endian
    arch->str[1] = (arch->size >> 24) & 0xFF;
    arch->str[2] = (arch->size >> 16) & 0xFF;
    arch->str[3] = (arch->size >> 8) & 0xFF;
    arch->str[4] = arch->size & 0xFF;

    return 1;
}


// Estruturas globais (assuma que essas são declaradas como extern em um header, se modularizado)
PeerList* peerlist;
pthread_mutex_t peerlist_mutex;

Archive* active_arch;
pthread_rwlock_t archive_lock;

uint32_t myaddr;

// Função auxiliar para publicar o histórico para todos os peers
void publish_archive() {
    pthread_rwlock_rdlock(&archive_lock);

    printf("\n----------Publishing new archive!----------\n");
    printf("Sending archive (%u bytes, %u messages):\n", active_arch->len, active_arch->size);

    // Log detalhado do conteúdo do archive
    for (uint32_t i = 5, msg_num = 1; i < active_arch->len; ) {
        uint8_t len = active_arch->str[i];
        printf("[Msg %2u] ", msg_num++);
        fwrite(active_arch->str + i + 1, 1, len, stdout);
        printf("\n");
        
        // Log do hash MD5
        uint8_t* md5 = active_arch->str + i + 1 + len + 16;
        printf("MD5: ");
        for (int j = 0; j < 16; j++) printf("%02x", md5[j]);
        printf("\n");
        
        i += 1 + len + 32;
    }

    // Envia para todos os peers, mesmo que pareça duplicado
    Node* aux = peerlist->head->next;
    while (aux) {
        printf("Sending to peer at sock %u\n", aux->sock);
        if (send(aux->sock, active_arch->str, active_arch->len, 0) == -1) {
            perror("Error sending archive to peer");
        }
        aux = aux->next;
    }

    pthread_rwlock_unlock(&archive_lock);
    printf("----------Done publishing!----------\n\n");
    fflush(stdout);
}


// Thread: envia PeerRequest a cada 5s e ArchiveRequest a cada 60s
void* peer_requester_thread(void* arg) {
    int peersock = *((int*) arg);
    uint8_t msg[2] = { MSG_PEERREQ, MSG_ARCHREQ };

    char filename[64];
    snprintf(filename, sizeof(filename), "%d.log", peersock);
    FILE* logfile = fopen(filename, "a");

    int count = 0;
    while (1) {
        if (send(peersock, msg, 1, 0) == -1) {
            fprintf(logfile, "Error sending peer request, broken pipe?\nTerminating requester thread.\n");
            pthread_exit(NULL);
        }

        count++;
        if (count == 12) {
            if (send(peersock, msg + 1, 1, 0) == -1) {
                fprintf(logfile, "Error sending archive request, broken pipe?\nTerminating requester thread.\n");
                pthread_exit(NULL);
            }
            count = 0;
        }

        sleep(5);
    }
}

// Thread: recebe mensagens e lida com cada tipo de mensagem
void* peer_receiver_thread(void* arg) {
    int peersock = *((int*) arg);
    delete (int*) arg;

    char filename[64];
    snprintf(filename, sizeof(filename), "%d.log", peersock);
    FILE* logfile = fopen(filename, "a");

    struct sockaddr_storage peeraddr;
    socklen_t peersize = sizeof(peeraddr);
    getpeername(peersock, (struct sockaddr*)&peeraddr, &peersize);
    struct sockaddr_in* peeraddr_in = (struct sockaddr_in*)&peeraddr;
    uint32_t upeerip = peeraddr_in->sin_addr.s_addr;
    char* cpeerip = inet_ntoa(peeraddr_in->sin_addr);

    pthread_mutex_lock(&peerlist_mutex);
    add_peer(peerlist, upeerip, peersock);
    fprintf(stdout, "Successfully connected to peer %s\n", cpeerip);

    // Envia ArchiveRequest imediatamente após conectar
    uint8_t archive_req = MSG_ARCHREQ;
    send(peersock, &archive_req, 1, 0);
    fprintf(logfile, "Sent immediate ArchiveRequest to %s\n", cpeerip);
    pthread_mutex_unlock(&peerlist_mutex);

    struct timeval tout;
    tout.tv_sec = 60;
    tout.tv_usec = 0;
    setsockopt(peersock, SOL_SOCKET, SO_RCVTIMEO, (char*)&tout, sizeof(tout));

    while (1) {
        uint8_t type;
        ssize_t n = recv(peersock, &type, 1, MSG_WAITALL);
        if (n <= 0) {
            fprintf(stderr, "Timeout or disconnect from peer %s.\n", cpeerip);
            close(peersock);
            pthread_mutex_lock(&peerlist_mutex);
            remove_peer(peerlist, upeerip);
            pthread_mutex_unlock(&peerlist_mutex);
            pthread_exit(NULL);
        }

        switch (type) {
            case MSG_PEERREQ:
                fprintf(logfile, "Received PeerRequest, sending list!\n");
                send(peersock, peerlist->str, 5 + 4 * peerlist->size, 0);
                break;

            case MSG_PEERLIST:
                fprintf(logfile, "Received PeerList.\n");
                process_peerlist(peersock, logfile);
                break;

            case MSG_ARCHREQ:
                fprintf(logfile, "Received ArchiveRequest!\n");
                pthread_rwlock_rdlock(&archive_lock);
                if (!active_arch->size) {
                    fprintf(logfile, "Current archive is empty, ignoring request.\n");
                    pthread_rwlock_unlock(&archive_lock);
                    break;
                }
                send(peersock, active_arch->str, active_arch->len, 0);
                pthread_rwlock_unlock(&archive_lock);
                break;

            case MSG_ARCHRESP:
                fprintf(logfile, "Received ArchiveResponse.\n");
                process_archive(peersock, logfile);
                break;

            case MSG_NOTIFY: {
                fprintf(logfile, "Received NotificationMessage!\n");
                uint8_t len;
                if (recv(peersock, &len, 1, MSG_WAITALL) <= 0) break;
                char notif[256] = {0};
                if (recv(peersock, notif, len, MSG_WAITALL) <= 0) break;
                fprintf(logfile, "[NOTIFY] %.*s\n", len, notif);
                break;
            }

            default:
                fprintf(logfile, "Unknown message type received: 0x%02x\n", type);
                uint8_t discard;
                while (recv(peersock, &discard, 1, MSG_DONTWAIT) > 0); // Descarta até o buffer limpar
                break;

        }
    }
}


// Thread: aceita conexões de peers
void* incoming_peers_thread(void*) {

    struct sockaddr_storage peeraddr;
    socklen_t peersize;
    int mysock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in localaddr{};
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = INADDR_ANY;  // aceita conexões em qualquer IP da máquina
    localaddr.sin_port = htons(51511);

    int opt = 1;
    setsockopt(mysock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(mysock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
        perror("bind failed");
        pthread_exit(NULL);
    }

    listen(mysock, 10);
    printf("[Incoming peers thread listening on port 51511]\n");

    while (1) {
        peersize = sizeof(peeraddr);
        int peersock = accept(mysock, (struct sockaddr*)&peeraddr, &peersize);
        if (peersock == -1) {
            perror("accept failed");
            continue;
        }

        pthread_t req, recv;
        pthread_create(&req, NULL, peer_requester_thread, new int(peersock));
        pthread_create(&recv, NULL, peer_receiver_thread, new int(peersock));
    }

    pthread_exit(NULL);
}

int init_peer_socket(char* ip) {
    struct addrinfo hints{}, *peerinfo, *aux;
    int sock = -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(ip, TCP_PORT, &hints, &peerinfo) != 0) {
        perror("getaddrinfo");
        return -1;
    }

    for (aux = peerinfo; aux != nullptr; aux = aux->ai_next) {
        sock = socket(aux->ai_family, aux->ai_socktype, aux->ai_protocol);
        if (sock == -1) continue;

        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, aux->ai_addr, aux->ai_addrlen);

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
       //struct timeval timeout {0, 500000};
        struct timeval timeout {2, 0};

        if (select(sock + 1, NULL, &fdset, NULL, &timeout) == 1) {
            int err;
            socklen_t len = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) {
                printf("Successfully connected to %s\n", ip);
                int flags = fcntl(sock, F_GETFL);
                flags &= ~O_NONBLOCK;
                fcntl(sock, F_SETFL, flags);
                break;
            } else {
                printf("Connection failed to %s with error: %d\n", ip, err);
                close(sock);
                continue;
            } 
        } else {
            printf("Connection timeout to %s\n", ip);
            close(sock);
            continue;
        }
    }
    

    freeaddrinfo(peerinfo);
    return (aux == nullptr) ? -1 : sock;
}

void process_peerlist(int peersock, FILE* logfile) {
    uint8_t buf[4];
    recv(peersock, buf, 4, MSG_WAITALL);
    uint32_t size = ((buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]);

    fprintf(logfile, "\n----------Processing peer list!----------\n");
    fprintf(logfile, "%u clients:\n", size);

    for (uint32_t i = 0; i < size; ++i) {
        recv(peersock, buf, 4, MSG_WAITALL);
        uint32_t uip = ((buf[3] << 24) | (buf[2] << 16) | (buf[1] << 8) | buf[0]);

        fprintf(logfile, "%d.%d.%d.%d\n", buf[0], buf[1], buf[2], buf[3]);
        if (uip == myaddr) continue;

        pthread_mutex_lock(&peerlist_mutex);
        if (!is_connected(peerlist, uip)) {
            char ip[17];
            snprintf(ip, 17, "%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3]);
            fprintf(stdout, "Attempting to connect to new peer %s...\n", ip);
            int newpeersock = init_peer_socket(ip);
            if (newpeersock == -1) {
                fprintf(stderr, "Failed to connect to peer %s!\n", ip);
                pthread_mutex_unlock(&peerlist_mutex);
                continue;
            }

            pthread_t req, recv;
            pthread_create(&req, NULL, peer_requester_thread, new int(newpeersock));
            pthread_create(&recv, NULL, peer_receiver_thread, new int(newpeersock));
        }
        pthread_mutex_unlock(&peerlist_mutex);
    }

    fprintf(logfile, "----------Done processing peerlist!----------\n\n");
}

void process_archive(int peersock, FILE* logfile) {
    fprintf(logfile, "\n----------Processing ArchiveResponse!---------\n");

    // Lê o tamanho (4 bytes após o tipo)
    uint8_t buf[4];
    if (recv(peersock, buf, 4, MSG_WAITALL) <= 0) {
        fprintf(logfile, "Failed to read archive size.\n");
        return;
    }
    uint32_t usize = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    fprintf(logfile, "Number of chats: %u\n", usize);

    // Aloca espaço suficiente
    uint32_t alloc_len = 5 + usize * 289;
    uint8_t* buffer = (uint8_t*) malloc(alloc_len);
    if (!buffer) return;

    buffer[0] = MSG_ARCHRESP;
    memcpy(buffer + 1, buf, 4);

    uint8_t* ptr = buffer + 5;
    uint32_t total_len = 5;

    for (uint32_t i = 0; i < usize; ++i) {
        uint8_t msglen;
        if (recv(peersock, &msglen, 1, MSG_WAITALL) <= 0) break;

        uint8_t msg[256] = {0};
        if (recv(peersock, msg, msglen, MSG_WAITALL) <= 0) break;

        uint8_t codes[32] = {0};
        if (recv(peersock, codes, 32, MSG_WAITALL) <= 0) break;

        // Verifica o hash MD5
        uint8_t* code = codes;
        uint8_t* md5 = code + 16;
        uint16_t* check = (uint16_t*) md5;
        
        fprintf(logfile, "Chat %d MD5 starts with: %02x%02x\n", i+1, md5[0], md5[1]);
        if (*check != 0) {
            fprintf(logfile, "Invalid MD5 hash for chat %d - ignoring archive\n", i+1);
            free(buffer);
            return;
        }

        // Copia para o buffer
        *ptr++ = msglen;
        memcpy(ptr, msg, msglen); ptr += msglen;
        memcpy(ptr, codes, 32); ptr += 32;
        total_len += (1 + msglen + 32);
    }

    // Cria nova archive
    Archive* new_archive = new Archive;
    new_archive->str = (uint8_t*) realloc(buffer, total_len);
    new_archive->len = total_len;
    new_archive->size = usize;
    new_archive->offset = 5;

    // Sempre substitui se o novo histórico for maior
    pthread_rwlock_wrlock(&archive_lock);
    if (new_archive->size > active_arch->size) {
        free(active_arch->str);
        delete active_arch;
        active_arch = new_archive;
        fprintf(stdout, "---------- Active archive replaced! ----------\n");
        publish_archive();
    } else {
        free(new_archive->str);
        delete new_archive;
        fprintf(logfile, "Archive not replaced (not larger than current)\n");
    }
    pthread_rwlock_unlock(&archive_lock);
    
    fprintf(logfile, "----------Done processing ArchiveResponse!----------\n\n");
}



int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./blockchain <initial_peer_ip> <local_ip>\n");
        return 0;
    }

    struct in_addr testing;
    inet_aton(argv[2], &testing);
    myaddr = testing.s_addr;

    peerlist = init_list();
    pthread_mutex_init(&peerlist_mutex, NULL);

    active_arch = init_archive();
    pthread_rwlock_init(&archive_lock, NULL);

    pthread_t incoming_thread;
    pthread_create(&incoming_thread, NULL, incoming_peers_thread, NULL);

    int sock = init_peer_socket(argv[1]);
    if (sock != -1) {
        pthread_t reqthread, recvthread;
        pthread_create(&reqthread, NULL, peer_requester_thread, new int(sock));
        pthread_create(&recvthread, NULL, peer_receiver_thread, new int(sock));
    }

    while (1) {
        uint8_t msg[256];
        memset(msg, 0, 256);
        printf("Input a chat message to send (255 chars max):\n");
        fgets((char*)msg, 256, stdin);

        pthread_rwlock_wrlock(&archive_lock);

        if (strcmp((char*)msg, "exit\n") == 0)
            exit(0);

        if (!add_message(active_arch, msg)) {
            fprintf(stderr, "Invalid message! Try again :)\n");
            pthread_rwlock_unlock(&archive_lock);
            continue;
        }

        fprintf(stdout, "Message successfully added to archive!\n");
        publish_archive();
        pthread_rwlock_unlock(&archive_lock);
    }

    return 0;
}
