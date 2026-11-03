# Integração com o Wazuh (Modo 1 e Modo 2)

Contenção comum aos dois modos do mecanismo. A decisão continua no mecanismo; o Wazuh transporta o veredito, classifica, registra e executa o bloqueio nos *endpoints*. A mesma configuração atende os dois modos, porque ambos gravam o veredito no mesmo arquivo e com o mesmo contrato.

**Estado: validada no laboratório do Modo 1 em 03/11/2026, com contenção real de dispositivo não autorizado e de clone de MAC.**

## Fluxo

| Etapa | Onde | O que faz |
| --- | --- | --- |
| Decisão | `MecanismoP0f` (prober no Modo 1, analyzer no Modo 2) | Grava cada veredito em `/var/log/mecanismo/verdicts.jsonl` |
| Transporte | Agente Wazuh no `MecanismoP0f` | Lê o arquivo como JSON e envia ao manager (1514/tcp). Tem a *active response* desligada |
| Classificação | Manager (`WazuhServer`) | Regras 100500 a 100512, pelo campo `verdict` |
| Contenção | Agentes dos *endpoints* | `firewall-drop` (Linux) ou `netsh` (Windows) bloqueiam o `srcip` por 3600 s |

O bloqueio no roteador da filial (*blocklist* de IP e MAC) não faz parte desta versão e está registrado como trabalho futuro.

## Contrato do veredito

Campos que a integração usa. Os demais campos de cada modo seguem no registro e aparecem no alerta do Wazuh como evidência, sem efeito na regra.

| Campo | Valor | Uso |
| --- | --- | --- |
| `origem` | `mecanismo-p0f` | Identifica o mecanismo na regra 100500 |
| `mode` | `"1"` ou `"2"` | Informativo, aparece na descrição do alerta |
| `verdict` | Um dos cinco vereditos | Define a regra e o nível |
| `srcip` | IP do ativo avaliado | Lido pelos scripts de bloqueio do Wazuh |
| `ip`, `mac` | IP e MAC do ativo | Evidência |

| Modo | Quem grava | Situação |
| --- | --- | --- |
| 1 | `prober.py` v6 | Implementado neste ramo |
| 2 | `analyzer.py` | Já grava `mode`. Falta acrescentar `origem` e `srcip`, a fazer no laboratório do Modo 2 |

## Regras (`manager/var/ossec/etc/rules/mecanismo_rules.xml`)

| ID | Veredito | Nível | Grupo | Contenção |
| --- | --- | --- | --- | --- |
| 100500 | Qualquer, com `origem` igual a `mecanismo-p0f` | 0 | `mecanismo` | Não |
| 100501 | `consistent` | 3 | `mecanismo_conforme` | Não |
| 100502 | `inconclusive` | 7 | `mecanismo_analise` | Não |
| 100510 | `mismatch-possible-clone` | 12 | `mecanismo_contencao` | Sim |
| 100511 | `unauthorized-fingerprinted` | 12 | `mecanismo_contencao` | Sim |
| 100512 | `unauthorized-unresolved` | 12 | `mecanismo_contencao` | Sim |

## Trechos do `ossec.conf`

| Arquivo | Onde | Conteúdo |
| --- | --- | --- |
| `manager/trechos/ossec-manager.xml` | `WazuhServer` | Lista branca (`10.0.0.0/24` e `10.1.0.1`) e duas *active responses* (`firewall-drop` e `netsh`, `location` `all`, regras 100510 a 100512, 3600 s) |
| `agente-mecanismo/trechos/ossec-agente-mecanismo.xml` | `MecanismoP0f` | `localfile` do `verdicts.jsonl` em JSON e *active response* desligada |

O `aplicar_trechos.py` aplica cada trecho: `manager` ou `agente`. Ele guarda `ossec.conf.antes-mecanismo` na primeira execução, coloca os blocos entre marcadores `mecanismo-p0f` e pode ser rodado de novo sem duplicar nada. Use `--dry-run` para ver o resultado antes de gravar.

## Instalação

**Manager (`WazuhServer`):**

```bash
cd /root/mecanismo-p0f/wazuh
install -o root -g wazuh -m 660 manager/var/ossec/etc/rules/mecanismo_rules.xml /var/ossec/etc/rules/
python3 aplicar_trechos.py manager
/var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
/var/ossec/bin/wazuh-logtest < testes/vereditos-exemplo.txt
```

**Agente do mecanismo (`MecanismoP0f`):**

```bash
cd /root/mecanismo-p0f/wazuh
python3 aplicar_trechos.py agente
systemctl restart wazuh-agent
```

## Verificação

```bash
# manager: alertas do mecanismo
grep -E '"id":"1005(0[0-9]|1[0-9])"' /var/ossec/logs/alerts/alerts.json | tail -n 5
# endpoint Linux: execucao e bloqueio
tail -n 5 /var/ossec/logs/active-responses.log
iptables -S | grep -- '-s <IP>'
```

No Windows: `netsh advfirewall firewall show rule name=all | findstr /i wazuh` e o arquivo `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`. No *dashboard*, filtro `rule.groups: mecanismo`.
