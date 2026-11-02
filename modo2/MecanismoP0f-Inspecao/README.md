# MecanismoP0f-Inspecao (Modo 2, filial)

Sensor da filial do **Modo 2** do mecanismo de detecção e resposta a dispositivos não autorizados em redes legadas. O Modo 2 é a abordagem **passiva e de maior custo**: este servidor fica em linha, entre o switch não gerenciável e o roteador da filial, e vê o tráfego em claro antes da criptografia da VPN.

## Papel

Nenhum pacote é enviado aos dispositivos da filial. O servidor:

1. une as interfaces `ens3` e `ens4` em uma ponte transparente (`br0`), por onde passa todo o tráfego da LAN;
2. roda o p0f na ponte, em modo promíscuo, e obtém o *fingerprint* dos SYN que os dispositivos enviam espontaneamente, além de MTU e *uptime*;
3. roda o `sensor.py`, que associa cada *fingerprint* ao MAC observado na ponte e grava eventos estruturados em `events.jsonl`;
4. envia esses eventos à matriz (`10.0.0.12`, TCP 514) por rsyslog, pelo túnel VPN. A decisão é tomada lá, pelo `analyzer.py`.

## Identificação

| Item | Valor |
| --- | --- |
| Hostname | `MecanismoP0f-Inspecao` |
| Ponte | `br0`, com `ens3` e `ens4`, STP desligado e `forward-delay` 0 |
| IP de gerência da ponte | `10.1.0.10/24`, gateway e DNS `10.1.0.1` |
| MAC da ponte | `a2:98:55:29:6a:d5` |
| LAN monitorada | `10.1.0.0/24` |
| Destino dos eventos | `MecanismoP0f` do Modo 2, `10.0.0.12`, TCP 514 |
| Fuso do sistema | `America/Sao_Paulo`. Os eventos são gravados em UTC |

## Conteúdo desta pasta

Os arquivos estão no mesmo caminho que ocupam no servidor.

| Arquivo | Função |
| --- | --- |
| `opt/mecanismo/sensor.py` | Associa *fingerprint* e MAC e grava `events.jsonl` |
| `etc/systemd/system/mecanismo-p0f.service` | p0f na ponte |
| `etc/systemd/system/mecanismo-sensor.service` | Sensor |
| `etc/rsyslog.d/60-mecanismo.conf` | Envio do `events.jsonl` à matriz |
| `etc/netplan/01-bridge.yaml` | Criação da ponte `br0` |
| `root/.ssh/config` | Chave de acesso deste servidor ao GitHub |

## Serviços

| Serviço | Comando |
| --- | --- |
| `mecanismo-p0f` | `/usr/sbin/p0f -i br0 -p -f /etc/p0f/p0f.fp -o /var/log/p0f/p0f.log -s /run/p0f/p0f.sock` |
| `mecanismo-sensor` | `/usr/bin/python3 /opt/mecanismo/sensor.py` |

| Opção do p0f | Função |
| --- | --- |
| `-i br0` | Escuta a ponte, onde passa o tráfego das duas interfaces |
| `-p` | Modo promíscuo |
| `-f` | Base de assinaturas |
| `-o` | Log em `/var/log/p0f/p0f.log` |
| `-s` | *Socket* de consulta em `/run/p0f/p0f.sock` |

```bash
systemctl status mecanismo-p0f mecanismo-sensor
journalctl -u mecanismo-sensor -f
tail -f /var/log/mecanismo/events.jsonl
```

## Eventos gravados (`/var/log/mecanismo/events.jsonl`)

Cada linha é um JSON com, no mínimo, `mac`, `ip`, `kind`, `source`, `ts` (UTC), `site` e `mode`. Tipos observados em 02/11/2026:

| `kind` | `source` | Conteúdo adicional |
| --- | --- | --- |
| `fingerprint` | `bridge-syn` | `p0f_os`, `dist`, `raw_sig`, `params`, `hostname`, `class_id` |
| `mtu` | `bridge-mtu` | `link`, `raw_mtu` |
| `uptime` | `bridge-uptime` | `uptime`, `raw_freq` |

Exemplo real:

```json
{"mac": "a2:98:55:29:6a:d5", "ip": "10.1.0.10", "kind": "fingerprint", "source": "bridge-syn", "hostname": null, "class_id": null, "p0f_os": "Linux 2.2.x-3.x", "dist": "0", "raw_sig": "4:64+0:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0", "params": "generic", "ts": "2026-11-02T15:01:14+00:00", "site": "MecanismoP0f-Inspecao", "mode": "2"}
```

## Envio à matriz (`60-mecanismo.conf`)

- O módulo `imfile` acompanha o `/var/log/mecanismo/events.jsonl` e marca cada linha com a tag `mecanismo` e a *facility* `local5`.
- Tudo o que é `local5` vai para `10.0.0.12:514` por TCP.
- A fila em disco (`mec_fwd`, até 500 MB, preservada no desligamento) e as tentativas sem limite fazem com que os eventos não se percam se o túnel cair; eles são enviados quando a conexão volta.

## Dados gerados (fora do Git)

| Arquivo | Conteúdo |
| --- | --- |
| `/var/log/mecanismo/events.jsonl` | Eventos do sensor |
| `/var/log/p0f/p0f.log` | Saída do p0f |

## Itens que não estão no repositório

| Item | Função | Como recriar |
| --- | --- | --- |
| `/root/.ssh/github_mecanismo` e `.pub` | Acesso deste servidor ao repositório | `ssh-keygen` e cadastro como *Deploy key* com escrita |
| `/root/.ssh/known_hosts` | Chave de host do GitHub | Gravado na primeira conexão |

## Pontos de atenção

- **Ponto único de falha.** O servidor está em linha. Se ele desligar, a LAN da filial perde a ligação com o roteador.
- **O sensor aparece no próprio tráfego.** As conexões do servidor (por exemplo, `git` e `ssh`) geram eventos com o IP `10.1.0.10` e o MAC da ponte. A matriz trata isso com a entrada `Sensor-Ponte` no `baseline_2.json`. Se o MAC da ponte mudar, essa entrada precisa ser atualizada.
- **Relógio no boot.** A VM liga com o relógio cerca de 3 h atrasado, e o NTP corrige alguns minutos depois. Antes de iniciar um teste, confirme `System clock synchronized: yes` no `timedatectl`.
- **Permissão do netplan.** O `01-bridge.yaml` precisa de permissão `600`. O Git não guarda essa permissão, então ela é reaplicada na reinstalação.
- **Histórico.** Em 02/11/2026 foi retirado o `/etc/rsyslog.d/10-mecanismo.conf`, uma versão anterior do envio que lia o mesmo arquivo e enviava cada evento em dobro à matriz. A cópia ficou em `/root/10-mecanismo.conf.removido`.

## Reinstalação a partir do repositório

Os comandos abaixo **sobrescrevem** os arquivos de mesmo nome no servidor. O passo da rede derruba a conexão por alguns segundos: execute-o pelo console, não por SSH.

1. Pacotes:

   ```bash
   apt update
   apt install -y p0f rsyslog python3 tcpdump git
   ```

2. Arquivos do repositório:

   ```bash
   cd /root/mecanismo-p0f/modo2/MecanismoP0f-Inspecao
   cp -rv opt etc /
   chmod 755 /opt/mecanismo/sensor.py
   chmod 600 /etc/netplan/01-bridge.yaml
   install -m 600 root/.ssh/config /root/.ssh/config
   ```

3. Ponte de rede (pelo console):

   ```bash
   netplan apply
   ip -br addr show br0
   ```

4. Diretórios, serviços e rsyslog:

   ```bash
   mkdir -p /var/log/mecanismo /var/log/p0f
   systemctl daemon-reload
   systemctl enable --now mecanismo-p0f mecanismo-sensor
   rsyslogd -N1
   systemctl restart rsyslog
   ```

## Como atualizar este repositório

Outros servidores também enviam para este repositório, então comece sempre pelo `git pull`:

```bash
cd /root/mecanismo-p0f
git pull
cp --parents /opt/mecanismo/sensor.py modo2/MecanismoP0f-Inspecao/
git add modo2/MecanismoP0f-Inspecao
git commit -m "[modo2/MecanismoP0f-Inspecao] descricao da alteracao"
git push
```

## Documentação de referência

- Registro de Configuração Inicial, Modo 2 (31/10/2026)
- Matriz do Modo 2: `modo2/MecanismoP0f`
