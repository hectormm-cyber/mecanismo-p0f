
# MecanismoP0f (Modo 1)

Servidor de monitoramento do **Modo 1** do mecanismo de detec‡ao e resposta a dispositivos nao autorizados em redes legadas. O Modo 1 ‚ a abordagem **ativa e de menor custo**.

## Papel

O servidor fica na LAN da matriz e nao vˆ o tr fego da filial. Ele descobre os dispositivos pelo que o roteador da filial informa atrav‚s do t£nel VPN, sonda cada dispositivo e lˆ o *fingerprint* da resposta com o p0f. A coleta ‚ ativa e a an lise ‚ passiva.

1. **Presen‡a pelo DHCP:** o roteador envia o log DHCP por Syslog (UDP 514).
2. **Presen‡a pelo ARP:** o servidor acessa o roteador por SSH, dispara uma varredura da LAN (`/tool ip-scan`) e lˆ a tabela ARP e os leases DHCP. Cobre hosts com IP est tico.
3. **Sondagem:** `ping` e `nmap -sT` no IP detectado. O p0f lˆ o SYN+ACK de resposta.
4. **Decisao:** compara‡ao com o *baseline* (MAC ou prefixo, portas, saltos, fam¡lia de SO e *Class-Id*) e grava‡ao do veredito.

## Identifica‡ao

| Item | Valor |
| --- | --- |
| Hostname | `MecanismoP0f` |
| IP | `10.0.0.12`, LAN da matriz (`10.0.0.0/24`) |
| Interface de captura do p0f | `ens3` |
| Rel¢gio | UTC, com NTP |
| Roteador da filial | `CHR-FILIAL`, `10.1.0.1`, RouterOS 6.40.4, tamb‚m em UTC com NTP |
| LAN monitorada | `10.1.0.0/24` |

## Conte£do desta pasta

Os arquivos estao no mesmo caminho que ocupam no servidor.

| Arquivo | Versao | Fun‡ao | Lˆ | Grava |
| --- | --- | --- | --- | --- |
| `opt/mecanismo/detector.py` | v2 | Presen‡a pelo log DHCP | `mikrotik.log`, `baseline.json` | `events.jsonl` |
| `opt/mecanismo/arp_poller.py` | v2 | Varredura, tabela ARP e leases por SSH | Roteador, `baseline.json`, `events.jsonl` | `events.jsonl` |
| `opt/mecanismo/prober.py` | v5 | Sondagem, *fingerprinting* e decisao | `events.jsonl`, `p0f.log`, `baseline.json` | `verdicts.jsonl`, `alerts.jsonl` |
| `opt/mecanismo/resumo.py` | | Resumo de eventos e vereditos, com latˆncia | `events.jsonl`, `verdicts.jsonl` | Tela |
| `opt/mecanismo/baseline.json` | | Padroes de ativos autorizados | | |
| `etc/rsyslog.d/10-filial.conf` | | Recebe Syslog em UDP 514 e separa o que vem do `CHR-FILIAL` | | `/var/log/filial/mikrotik.log` |
| `etc/systemd/system/mecanismo.target` | | Agrupa os quatro servi‡os | | |
| `etc/systemd/system/mecanismo-*.service` | | p0f, prober, detector e poller ARP | | |
| `root/.ssh/config` | | Exce‡ao de SSH com SHA-1 s¢ para `10.1.0.1` e chave do GitHub | | |

## Servi‡os

| Servi‡o | Comando |
| --- | --- |
| `mecanismo-p0f` | `p0f -i ens3 -f /etc/p0f/p0f.fp -o /var/log/p0f/p0f.log tcp` |
| `mecanismo-prober` | `prober.py --probe-authorized` |
| `mecanismo-detector` | `detector.py` |
| `mecanismo-arp` | `arp_poller.py` |

- O `--probe-authorized` ‚ obrigat¢rio: sem ele o prober ignora os MACs autorizados, e um clone de MAC nunca seria sondado.
- O prober sobe antes do detector e do poller, porque lˆ o `events.jsonl` a partir do fim.
- Parar ou reiniciar o `mecanismo.target` propaga para os quatro servi‡os.

```bash
systemctl status mecanismo.target
systemctl restart mecanismo.target
journalctl -u mecanismo-arp -f
python3 /opt/mecanismo/resumo.py 2026-11-01T20:45:00
python3 /opt/mecanismo/prober.py --ip 10.1.0.198
```

## *Baseline*

A chave ‚ o MAC completo ou o prefixo do fabricante (trˆs primeiros bytes). A entrada do MAC completo tem prioridade sobre a do prefixo.

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

| Campo | Uso na decisao |
| --- | --- |
| Chave | Fator MAC: define `authorized` ou `unknown` |
| `ports` | As portas abertas para o mecanismo devem ser exatamente estas |
| `dist` | Saltos medidos pelo p0f ou estimados pelo TTL |
| `os` | Fam¡lia de SO observada |
| `class_id` | *Class-Id* do DHCP, comparado s¢ em eventos vindos de DHCP |
| `name`, `hardware` | Informativos |

## Dados gerados (fora do Git)

| Arquivo | Conte£do |
| --- | --- |
| `/var/log/filial/mikrotik.log` | Log DHCP bruto do roteador |
| `/var/log/mecanismo/events.jsonl` | Eventos de presen‡a (detector e poller) |
| `/var/log/mecanismo/verdicts.jsonl` | Todos os vereditos |
| `/var/log/mecanismo/alerts.jsonl` | S¢ os vereditos que geram alerta |
| `/var/log/p0f/p0f.log` | Sa¡da do p0f |

As evidˆncias de cada rodada de testes sao arquivadas fora do reposit¢rio.

## Itens que nao estao no reposit¢rio

| Item | Fun‡ao | Como recriar |
| --- | --- | --- |
| `/root/.ssh/mecanismo_rsa` e `.pub` | Acesso do servidor ao usu rio `monitor` do roteador | `ssh-keygen` e importa‡ao no RouterOS (abaixo) |
| `/root/.ssh/github_mecanismo` e `.pub` | Acesso do servidor a este reposit¢rio | `ssh-keygen` e cadastro como *Deploy key* com escrita |
| `/root/.ssh/known_hosts` | Chaves de host do roteador e do GitHub | Gravado na primeira conexao |

## Reinstala‡ao a partir do reposit¢rio

Os comandos abaixo **sobrescrevem** os arquivos de mesmo nome no servidor.

1. Pacotes:

   ```bash
   apt update
   apt install -y rsyslog p0f nmap hping3 tcpdump python3 git
   ```

2. Arquivos do reposit¢rio:

   ```bash
   cd /root/mecanismo-p0f/modo1/MecanismoP0f
   cp -rv opt etc /
   install -m 600 root/.ssh/config /root/.ssh/config
   ```

3. Diret¢rios de log e rsyslog:

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

5. Servi‡os:

   ```bash
   systemctl daemon-reload
   systemctl enable --now mecanismo.target
   systemctl status mecanismo.target
   ```

## Como atualizar este reposit¢rio

Depois de alterar um arquivo no servidor, copie-o para c  mantendo o caminho e envie:

```bash
cd /root/mecanismo-p0f
cp --parents /opt/mecanismo/prober.py modo1/MecanismoP0f/
git add modo1/MecanismoP0f
git commit -m "[modo1/MecanismoP0f] descri‡ao da altera‡ao"
git push
```

## Documenta‡ao de referˆncia

- Registro de Configura‡ao e Evidˆncias do Laborat¢rio, Modo 1, rodada 1 (13 a 18/10/2026)
- Registro Complementar, Modo 1, rodada 2 (01 e 02/11/2026)

A configura‡ao do roteador `CHR-FILIAL` ser  versionada em `modo1/CHR-FILIAL/`.

