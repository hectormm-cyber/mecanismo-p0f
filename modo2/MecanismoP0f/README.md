# MecanismoP0f (Modo 2, matriz)

Servidor de decisão do **Modo 2** do mecanismo de detecção e resposta a dispositivos não autorizados em redes legadas (TCC de Segurança da Informação, UNISINOS). O Modo 2 é a abordagem **passiva e de maior custo**: um sensor em ponte na filial (`MecanismoP0f-Inspecao`) vê o tráfego antes da VPN e envia os eventos para este servidor, que decide.

## Papel

Este servidor não captura tráfego, não sonda nenhum host e não acessa o roteador. Ele:

1. recebe por rsyslog (TCP 514, pelo túnel VPN) os eventos enviados pelo sensor de cada filial;
2. grava os eventos em um arquivo por filial;
3. correlaciona presença e *fingerprint* passivo por MAC e IP e compara com o *baseline*;
4. grava o veredito e, quando for o caso, o alerta.

## Identificação

| Item | Valor |
| --- | --- |
| Hostname | `MecanismoP0f`, no laboratório do Modo 2 |
| IP | `10.0.0.12`, LAN da matriz. É o mesmo IP do `MecanismoP0f` do Modo 1, que fica em outro laboratório |
| Fuso do sistema | `America/Sao_Paulo` (o servidor do Modo 1 está em UTC) |
| Filial atendida | `MecanismoP0f-Inspecao`, `10.1.0.10`, LAN `10.1.0.0/24` |

## Conteúdo desta pasta

Os arquivos estão no mesmo caminho que ocupam no servidor.

| Arquivo | Função | Lê | Grava |
| --- | --- | --- | --- |
| `opt/mecanismo/analyzer.py` | Decisão centralizada | `/var/log/filiais/*/events.jsonl`, `baseline_2.json` | `verdicts.jsonl`, `alerts.jsonl` |
| `opt/mecanismo/baseline_2.json` | *Baseline* do Modo 2 | | |
| `etc/rsyslog.d/20-modo2.conf` | Receptor dos eventos das filiais em TCP 514 | | `/var/log/filiais/<hostname>/events.jsonl` |
| `etc/systemd/system/mecanismo-analyzer.service` | Serviço do analyzer | | |
| `root/.ssh/config` | Chave de acesso deste servidor ao GitHub | | |

## Receptor rsyslog (`20-modo2.conf`)

- Escuta em TCP 514 (`imtcp`), com um *ruleset* próprio (`filiais`).
- Grava apenas as mensagens com `programname` igual a `mecanismo`. Qualquer outra mensagem que chegue nessa porta é descartada (`stop`).
- O *template* `RawJson` extrai da mensagem só o JSON, sem o cabeçalho do Syslog.
- Cada filial ganha o seu arquivo, `/var/log/filiais/<hostname>/events.jsonl`. O diretório é criado automaticamente.

## Analyzer

Parâmetros definidos no início do código:

| Constante | Valor | Observação |
| --- | --- | --- |
| `EVENTS` | `/var/log/filiais` | Um subdiretório por filial |
| `OUT` | `/var/log/mecanismo/verdicts.jsonl` | Todos os vereditos |
| `ALERTS` | `/var/log/mecanismo/alerts.jsonl` | Só os vereditos que geram alerta |
| `BASELINE` | `/opt/mecanismo/baseline_2.json` | |
| `COOLDOWN` | 300 s | Tempo sem reavaliar o mesmo par (MAC, IP) |
| `GRACE` | 120 s | Espera por um *fingerprint* antes de decidir |

Os vereditos que geram alerta estão em `ALERT_VERDICTS`, no código (entre eles `mismatch-possible-clone` e `unauthorized-fingerprinted`).

Exemplo de veredito real, do próprio sensor da filial:

```json
{"ts": "2026-11-02T12:24:21Z", "mode": "2", "site": "MecanismoP0f-Inspecao", "ip": "10.1.0.10", "mac": "a2:98:55:29:6a:d5", "name": "Sensor-Ponte", "status": "authorized", "match": "mac", "hostname": null, "dhcp_class_id": null, "expected_os": "Linux", "expected_dist": 0, "expected_sig": null, "p0f_os": "Linux 2.2.x-3.x", "dist": "0", "raw_sig": "4:64+0:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0", "sig_core": "4:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0", "link": null, "uptime": "40 days 10 hrs 3 min (modulo 49 days)", "observed_family": "Linux", "method": "p0f-passive", "sources": ["bridge-syn", "bridge-uptime"], "ip_prev_mac": null, "verdict": "consistent", "reasons": [], "alert": false}
```

| Campo | Significado |
| --- | --- |
| `site`, `mode` | Filial de origem e modo |
| `match` | Como o MAC casou no *baseline* (`mac` ou `oui`) |
| `expected_os`, `expected_dist`, `expected_sig` | Valores do *baseline* para o ativo |
| `raw_sig` | Assinatura bruta do p0f |
| `sig_core` | A mesma assinatura sem o campo de TTL, usada na comparação |
| `method` | `p0f-passive`: nenhum pacote foi enviado ao ativo |
| `sources` | Tipos de evento do sensor usados no veredito |

O `ts` desse exemplo foi gravado antes de o relógio do servidor sincronizar (ver Pontos de atenção).

## *Baseline* (`baseline_2.json`)

A chave segue a regra do Modo 1: MAC completo ou prefixo do fabricante (três primeiros bytes), com prioridade para o MAC completo. Diferenças em relação ao *baseline* do Modo 1:

| Fator | Modo 1 | Modo 2 |
| --- | --- | --- |
| `dist` | 2 (dois roteadores no caminho) | 0 (mesmo segmento da ponte) |
| `ports` | Verificado pelo `nmap -sT` | Não existe, porque nada é sondado |
| Assinatura TCP/IP | Gravada, sem decidir | Decide, comparada sem o TTL (`sig_core`) |

O *baseline* atual inclui a entrada `Sensor-Ponte` (MAC `a2:98:55:29:6a:d5`, Linux, `dist` 0). Ela existe porque o sensor também aparece no tráfego da ponte; sem ela, o próprio sensor seria tratado como dispositivo desconhecido.

## Serviço

| Serviço | Comando |
| --- | --- |
| `mecanismo-analyzer` | `/usr/bin/python3 /opt/mecanismo/analyzer.py` |

O serviço depende do `rsyslog`, reinicia sozinho em caso de falha (`Restart=always`) e sobe no boot (`WantedBy=multi-user.target`).

```bash
systemctl status mecanismo-analyzer
journalctl -u mecanismo-analyzer -f
ss -lntp | grep 514
tail -f /var/log/filiais/*/events.jsonl
tail -f /var/log/mecanismo/verdicts.jsonl
```

## Dados gerados (fora do Git)

| Arquivo | Conteúdo |
| --- | --- |
| `/var/log/filiais/<hostname>/events.jsonl` | Eventos recebidos de cada filial |
| `/var/log/mecanismo/verdicts.jsonl` | Todos os vereditos |
| `/var/log/mecanismo/alerts.jsonl` | Só os vereditos que geram alerta |

## Itens que não estão no repositório

| Item | Função | Como recriar |
| --- | --- | --- |
| `/root/.ssh/github_mecanismo` e `.pub` | Acesso deste servidor ao repositório | `ssh-keygen` e cadastro como *Deploy key* com escrita |
| `/root/.ssh/known_hosts` | Chave de host do GitHub | Gravado na primeira conexão |
| `/opt/mecanismo/baseline.json.modo1` | Cópia de segurança do *baseline* do Modo 1 | Não é usado pelo analyzer |

## Pontos de atenção

- **Relógio no boot.** A VM liga com o relógio cerca de 3 h atrasado, e o NTP corrige alguns minutos depois. Vereditos gravados nesse intervalo ficam com o `ts` errado (o exemplo acima é um deles). Antes de iniciar um teste, confirme `System clock synchronized: yes` no `timedatectl`.
- **Fuso diferente do Modo 1.** Este servidor está em `America/Sao_Paulo`; o do Modo 1, em UTC. Os campos `ts` dos JSON são gravados em UTC nos dois.
- **Firewall.** Se o `ufw` estiver ativo, a porta TCP 514 precisa estar liberada para a LAN da filial.

## Reinstalação a partir do repositório

Os comandos abaixo **sobrescrevem** os arquivos de mesmo nome no servidor.

1. Pacotes:

   ```bash
   apt update
   apt install -y rsyslog python3 git
   ```

2. Arquivos do repositório:

   ```bash
   cd /root/mecanismo-p0f/modo2/MecanismoP0f
   cp -rv opt etc /
   install -m 600 root/.ssh/config /root/.ssh/config
   ```

3. Diretórios, firewall e rsyslog:

   ```bash
   mkdir -p /var/log/filiais /var/log/mecanismo
   ufw allow from 10.1.0.0/24 to any port 514 proto tcp
   rsyslogd -N1
   systemctl restart rsyslog
   ```

4. Serviço:

   ```bash
   systemctl daemon-reload
   systemctl enable --now mecanismo-analyzer
   systemctl status mecanismo-analyzer
   ```

## Como atualizar este repositório

Outros servidores também enviam para este repositório, então comece sempre pelo `git pull`:

```bash
cd /root/mecanismo-p0f
git pull
cp --parents /opt/mecanismo/analyzer.py modo2/MecanismoP0f/
git add modo2/MecanismoP0f
git commit -m "[modo2/MecanismoP0f] descricao da alteracao"
git push
```

## Documentação de referência

- Registro de Configuração Inicial, Modo 2 (31/10/2026)
- Sensor da filial: `modo2/MecanismoP0f-Inspecao`
