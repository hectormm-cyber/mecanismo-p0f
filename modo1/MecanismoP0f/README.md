# MecanismoP0f (Modo 1)

Servidor de monitoramento do **Modo 1** do mecanismo de detecção e resposta a dispositivos não autorizados em redes legadas. O Modo 1 é a abordagem **ativa e de menor custo**.

## Papel

O servidor fica na LAN da matriz e não vê o tráfego da filial. Ele descobre os dispositivos pelo que o roteador da filial informa através do túnel VPN, sonda cada dispositivo e lê o *fingerprint* da resposta com o p0f. A coleta é ativa e a análise é passiva.

1. **Presença pelo DHCP:** o roteador envia o log DHCP por Syslog (UDP 514).
2. **Presença pelo ARP:** o servidor acessa o roteador por SSH, dispara uma varredura da LAN (`/tool ip-scan`) e lê a tabela ARP e os leases DHCP. Cobre hosts com IP estático.
3. **Sondagem:** `ping` e `nmap -sT` no IP detectado. O p0f lê o SYN+ACK de resposta.
4. **Decisão:** comparação com o *baseline* (MAC ou prefixo, portas, saltos, família de SO e *Class-Id*) e gravação do veredito.

## Identificação

| Item | Valor |
| --- | --- |
| Hostname | `MecanismoP0f` |
| IP | `10.0.0.12`, LAN da matriz (`10.0.0.0/24`) |
| Interface de captura do p0f | `ens3` |
| Relógio | UTC, com NTP |
| Roteador da filial | `CHR-FILIAL`, `10.1.0.1`, RouterOS 6.40.4, também em UTC com NTP |
| LAN monitorada | `10.1.0.0/24` |

## Conteúdo desta pasta

Os arquivos estão no mesmo caminho que ocupam no servidor.

| Arquivo | Versão | Função | Lê | Grava |
| --- | --- | --- | --- | --- |
| `opt/mecanismo/detector.py` | v2 | Presença pelo log DHCP | `mikrotik.log`, `baseline.json` | `events.jsonl` |
| `opt/mecanismo/arp_poller.py` | v2 | Varredura, tabela ARP e leases por SSH | Roteador, `baseline.json`, `events.jsonl` | `events.jsonl` |
| `opt/mecanismo/prober.py` | v6 | Sondagem, *fingerprinting* e decisão. Grava `mecanismo` e `srcip` para o Wazuh | `events.jsonl`, `p0f.log`, `baseline.json` | `verdicts.jsonl`, `alerts.jsonl` |
| `opt/mecanismo/resumo.py` | | Resumo de eventos e vereditos, com latência | `events.jsonl`, `verdicts.jsonl` | Tela |
| `opt/mecanismo/baseline.json` | | Padrões de ativos autorizados | | |
| `etc/rsyslog.d/10-filial.conf` | | Recebe Syslog em UDP 514 e separa o que vem do `CHR-FILIAL` | | `/var/log/filial/mikrotik.log` |
| `etc/systemd/system/mecanismo.target` | | Agrupa os quatro serviços | | |
| `etc/systemd/system/mecanismo-*.service` | | p0f, prober, detector e poller ARP | | |
| `root/.ssh/config` | | Exceção de SSH com SHA-1 só para `10.1.0.1` e chave do GitHub | | |

## Serviços

| Serviço | Comando |
| --- | --- |
| `mecanismo-p0f` | `p0f -i ens3 -f /etc/p0f/p0f.fp -o /var/log/p0f/p0f.log tcp` |
| `mecanismo-prober` | `prober.py --probe-authorized` |
| `mecanismo-detector` | `detector.py` |
| `mecanismo-arp` | `arp_poller.py` |

- O `--probe-authorized` é obrigatório: sem ele o prober ignora os MACs autorizados, e um clone de MAC nunca seria sondado.
- O prober sobe antes do detector e do poller, porque lê o `events.jsonl` a partir do fim.
- Parar ou reiniciar o `mecanismo.target` propaga para os quatro serviços.

```bash
systemctl status mecanismo.target
systemctl restart mecanismo.target
journalctl -u mecanismo-arp -f
python3 /opt/mecanismo/resumo.py 2026-11-01T20:45:00
python3 /opt/mecanismo/prober.py --ip 10.1.0.198
```

## *Baseline*

A chave é o MAC completo ou o prefixo do fabricante (três primeiros bytes). A entrada do MAC completo tem prioridade sobre a do prefixo.

```json
{
  "14:18:77": {
    "name": "Windows-Estacao",
    "hardware": "Dell",
    "os": "Windows",
    "ports": [445, 3389],
    "dist": 2,
    "class_id": "MSFT 5.0"
  }
}
```

| Campo | Uso na decisão |
| --- | --- |
| Chave | Fator MAC: define `authorized` ou `unknown` |
| `ports` | As portas abertas para o mecanismo devem ser exatamente estas |
| `dist` | Saltos medidos pelo p0f ou estimados pelo TTL |
| `os` | Família de SO observada |
| `class_id` | *Class-Id* do DHCP, comparado só em eventos vindos de DHCP |
| `name`, `hardware` | Informativos |

## Integração com o Wazuh

O `verdicts.jsonl` é enviado ao `WazuhServer` (`10.0.0.11`) por um agente Wazuh local, que lê o arquivo como JSON. As regras e a contenção estão em `modo1/WazuhServer/`. A *active response* fica desligada neste agente, para o mecanismo continuar sondando o ativo bloqueado.

## Dados gerados (fora do Git)

| Arquivo | Conteúdo |
| --- | --- |
| `/var/log/filial/mikrotik.log` | Log DHCP bruto do roteador |
| `/var/log/mecanismo/events.jsonl` | Eventos de presença (detector e poller) |
| `/var/log/mecanismo/verdicts.jsonl` | Todos os vereditos |
| `/var/log/mecanismo/alerts.jsonl` | Só os vereditos que geram alerta |
| `/var/log/p0f/p0f.log` | Saída do p0f |

As evidências de cada rodada de testes são arquivadas fora do repositório.

## Itens que não estão no repositório

| Item | Função | Como recriar |
| --- | --- | --- |
| `/root/.ssh/mecanismo_rsa` e `.pub` | Acesso do servidor ao usuário `monitor` do roteador | `ssh-keygen` e importação no RouterOS (abaixo) |
| `/root/.ssh/github_mecanismo` e `.pub` | Acesso do servidor a este repositório | `ssh-keygen` e cadastro como *Deploy key* com escrita |
| `/root/.ssh/known_hosts` | Chaves de host do roteador e do GitHub | Gravado na primeira conexão |

## Reinstalação a partir do repositório

Os comandos abaixo **sobrescrevem** os arquivos de mesmo nome no servidor.

1. Pacotes:

   ```bash
   apt update
   apt install -y rsyslog p0f nmap hping3 tcpdump python3 git
   ```

2. Arquivos do repositório:

   ```bash
   cd /root/mecanismo-p0f/modo1/MecanismoP0f
   cp -rv opt etc /
   install -m 600 root/.ssh/config /root/.ssh/config
   ```

3. Diretórios de log e rsyslog:

   ```bash
   mkdir -p /var/log/filial /var/log/mecanismo /var/log/p0f
   chown syslog:adm /var/log/filial
   systemctl restart rsyslog
   ```

4. Chave para o roteador:

   ```bash
   ssh-keygen -t rsa -b 4096 -N "" -f /root/.ssh/mecanismo_rsa
   scp -O /root/.ssh/mecanismo_rsa.pub 10.1.0.1:
   ```

   No roteador: `/user ssh-keys import public-key-file=mecanismo_rsa.pub user=monitor`.
   Teste no servidor: `ssh -i /root/.ssh/mecanismo_rsa monitor@10.1.0.1 '/system identity print'`.

5. Serviços:

   ```bash
   systemctl daemon-reload
   systemctl enable --now mecanismo.target
   systemctl status mecanismo.target
   ```

## Como atualizar este repositório

Depois de alterar um arquivo no servidor, copie-o para cá mantendo o caminho e envie:

```bash
cd /root/mecanismo-p0f
cp --parents /opt/mecanismo/prober.py modo1/MecanismoP0f/
git add modo1/MecanismoP0f
git commit -m "[modo1/MecanismoP0f] descrição da alteração"
git push
```

## Documentação de referência

- Registro de Configuração e Evidências do Laboratório, Modo 1, rodada 1 (13 a 18/10/2026)
- Registro Complementar, Modo 1, rodada 2 (01 e 02/11/2026)

A configuração do roteador `CHR-FILIAL` será versionada em `modo1/CHR-FILIAL/`.
