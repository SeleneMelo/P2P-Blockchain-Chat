***DCC Internet P2P Blockchain Chat***


Neste trabalho, você irá desenvolver um sistema de armazenamento de chats distribuído. O sistema funciona de forma par-a-par e utiliza um blockchain como mecanismo de verificação dos chats. O desenvolvimento do trabalho será dividido em três partes

Parte 0: Informações preliminares
Este trabalho pode ser implementado em qualquer linguagem de programação e utilizar qualquer função da biblioteca padrão da linguagem escolhida. Seu programa irá estabelecer diversas conexões de rede simultaneamente. Para controlar várias conexões, seu programa deverá utilizar múltiplas threads ou um mecanismo equivalente ao select().
Seu programa irá trocar informações com outros programas utilizando mensagens de rede com formato pré-definido. Mensagens são transmitidas pela rede como uma sequência ordenada de campos. Existem três tipos de campo: (1) inteiro sem sinal de 1 byte, (2) inteiro sem sinal de 4 bytes e (3) sequência de bytes. Os campos inteiros deverão ser transmitidos sempre em network byte order e no tamanho indicado. As sequências de caracteres dos chatsarmazenados usarão codificação ASCII (1 byte por caractere, sem acentos).

Parte 1: Identificação de pares e estabelecimento da rede P2P
Ao entrar no sistema, seu programa irá se conectar a um par previamente conhecido que já está no sistema. Após o estabelecimento da conexão com um par do sistema, seu programa irá requisitar e obter uma lista de outros pares no sistema. Após receber a lista de outros pares, seu programa deverá se conectar a todos os pares aos quais ainda não está conectado

Parte 2: Histórico de chats
O seu programa deve manter um histórico de todos os chats conhecidos. Sempre que um par cria um chat (parte 3), ele é inserido no histórico de chats. Nesta parte, seu programa deve implementar duas novas mensagens:
•	ArchiveRequest [0x3] (1 byte): Esta mensagem contém um inteiro de 1 byte com o valor 0x3. Esta mensagem não possui outros campos. Quando seu programa recebe uma mensagem deste tipo, ele deve responder com uma mensagem do tipo ArchiveResponse.
•	ArchiveResponse [0x4] (5 bytes + chats): Esta mensagem começa com um inteiro de 1 byte contendo o valor 0x4. Em seguida, há um inteiro de 4 bytes contendo o número C de chats no histórico. A mensagem contém então uma quantidade variável de bytes para cada chat enviado (descrito abaixo). Ao receber uma mensagem ArchiveResponse seu programa deve primeiro verificar se esse novo histórico é válido (descrito abaixo). Se o histórico não for válido, seu programa deve ignorá-lo. Se o histórico for válido, seu programa deve comparar se o novo histórico contém mais chats do que o histórico anterior. Se contiver, deverá substituir o histórico anterior pelo novo. Ao ignorar um histórico inválido ou que contém menos chats que o histórico anterior, seu programa não deve desconectar o peer (mas você pode considerar enviar uma mensagem de notificação).

Verificação de um histórico
Cada histórico é composto por uma sequência de chats. A sequência inteira de chats em um histórico é verificada computacionalmente. Um histórico é considerado válido se as condições abaixo forem satisfeitas:
1.	O hash MD5 do último chat deve começar com dois bytes zero.
2.	O hash MD5 do último chat deve ser igual ao hash MD5 calculado sobre uma sequência de bytes S. A sequência S é definida como a sequência de bytes dos últimos 20 chats no histórico (incluindo todos os 1 + N + 32 bytes de cada um dos últimos 20 chats), exceto os últimos 16 bytes do último chat (o hash MD5 do último chat).
3.	O histórico anterior, ou seja, o histórico sem a última mensagem, deve ser válido. Em outras palavras, os históricos de cada chat devem ser verificados recursivamente.
Se um histórico tem menos de 20 chats, todos seus chats devem ser considerados.
Note que, em média, apenas 1 em cada 65535 hashes MD5 possui os dois primeiros bytes iguais a zero. Para criar um chat e adicioná-lo ao histórico, seu programa deve minerar valores para o código verificador do seu chat até encontrar um valor que faça o MD5 calculado sobre a sequência S (formada pelo seu chat e pelos 19 chats precedentes) tenha os dois primeiros bytes iguais a zero. Em outras palavras, é preciso que seu programa gere códigos verificadores aleatoriamente e calcule o hash MD5 repetidamente até achar um hash MD5 com os dois primeiros bytes iguais a zero. Para que esse cálculo seja possível, os 16 bytes do hash MD5 do seu novo chat não são considerados durante o processo de mineração e de verificação do histórico (ou seja, os bytes do MD5 são considerados inexistentes).

Parte 3: Envio de chats
Para enviar um chat, seu programa precisa apenas obter o histórico atual e criar um novo histórico anexando seu novo chat. Para isso, é necessário minerar um código verificador que inclua sua mensagem no novo histórico. Ao criar um novo histórico, seu programa deve disseminá-lo (para evitar que outros históricos proliferem antes) enviando mensagens ArchiveResponse para todos os parceiros.

Parte 4: Mensagens de notificação (opcional)
Ao detectar um erro (p.ex., erro ao decodificar uma mensagem recebida, um arquivo inválido) ou situação inesperada (p.ex., receber um histórico menor que o corrente), seu programa pode enviar uma mensagem de notificação para informar o peer do ocorrido, facilitando a resolução de problemas.
