# WazuhServer (Modo 1)

Manager Wazuh que recebe os vereditos do mecanismo e executa a contenção nos *endpoints*. A decisão é do mecanismo; o Wazuh classifica, registra e dispara a *active response*.

## Papel

1. O agente Wazuh do `MecanismoP0f` lê `/var/log/mecanismo/verdicts.jsonl` (`log_format json`) e envia cada veredito ao manager.
2. As regras `100500` a `100512` classificam o veredito pelo campo `verdict`.
3. Os vereditos de alerta disparam a *active response* em todos os agentes: `firewall-drop` nos Linux e `netsh` nos Windows bloqueiam o `srcip` por 3600 s.
4. O agente do `MecanismoP0f` tem a *active response* desligada, para continuar sondando o ativo bloqueado.

O bloqueio no roteador da filial (*blocklist* de IP e MAC no CHR-FILIAL) não faz parte desta versão e está registrado como trabalho futuro.

## Identificação

| Item | Valor |
| --- | --- |
| Hostname | `WazuhServer` |
| IP | `10.0.0.11`, LAN da matriz (`10.0.0.0/24`) |
| Sistema | Ubuntu 24.04.1 LTS, 4 vCPU, 7,8 GiB de RAM |
| Wazuh | 4.14.8, instalação *all-in-one* (manager, indexer, dashboard e filebeat) |
| Portas usadas pelos agentes | 1514/tcp (eventos) e 1515/tcp (cadastro) |

## Regras

Arquivo `var/ossec/etc/rules/mecanismo_rules.xml`. Faixa reservada: `100500` a `100599`.

| ID | Veredito | Nível | Grupo | Contenção |
| --- | --- | --- | --- | --- |
| 100500 | Qualquer veredito com `"mecanismo": "modo1"` | 0 | `mecanismo` | Não |
| 100501 | `consistent` | 3 | `mecanismo_conforme` | Não |
| 100502 | `inconclusive` | 7 | `mecanismo_analise` | Não |
| 100510 | `mismatch-possible-clone` | 12 | `mecanismo_contencao` | Sim |
| 100511 | `unauthorized-fingerprinted` | 12 | `mecanismo_contencao` | Sim |
| 100512 | `unauthorized-unresolved` | 12 | `mecanismo_contencao` | Sim |

As regras dependem de dois campos acrescentados no `prober.py` v6: `mecanismo`, que identifica a origem, e `srcip`, que os scripts de bloqueio do Wazuh leem.

## Trechos do `ossec.conf`

Arquivo `trechos/ossec-manager.xml`, aplicado pelo `aplicar_trechos.py`:

| Trecho | Onde entra | Função |
| --- | --- | --- |
| `<white_list>10.0.0.0/24</white_list>` e `<white_list>10.1.0.1</white_list>` | Bloco `<global>` | Nenhuma *active response* bloqueia a LAN da matriz nem o roteador da filial |
| `<active-response>` com `firewall-drop` | Antes do último `</ossec_config>`, entre marcadores `mecanismo-modo1` | Bloqueio nos agentes Linux |
| `<active-response>` com `netsh` | Idem | Bloqueio nos agentes Windows |

Os comandos `firewall-drop` e `netsh` já vêm definidos na instalação do Wazuh. Com `location` igual a `all`, cada agente recebe os dois e executa apenas o do próprio sistema.

O script é idempotente: rodado de novo, não duplica a lista branca e substitui o conteúdo entre os marcadores. Na primeira execução guarda `ossec.conf.antes-mecanismo`.

## Instalação a partir do repositório

1. Repositório no servidor (com *deploy key*, como no `MecanismoP0f`) ou cópia desta pasta para `/root/mecanismo-p0f/modo1/WazuhServer`.

2. Regras:

   ```bash
   cd /root/mecanismo-p0f/modo1/WazuhServer
   install -o root -g wazuh -m 660 var/ossec/etc/rules/mecanismo_rules.xml /var/ossec/etc/rules/
   ```

3. Trechos do `ossec.conf`, primeiro em simulação:

   ```bash
   python3 aplicar_trechos.py --dry-run | grep -n -A2 -B2 'white_list\|mecanismo-modo1'
   python3 aplicar_trechos.py
   ```

4. Validação e reinício:

   ```bash
   /var/ossec/bin/wazuh-analysisd -t && systemctl restart wazuh-manager
   systemctl is-active wazuh-manager
   ```

5. Teste das regras sem agente, com as cinco linhas de `testes/vereditos-exemplo.txt`:

   ```bash
   /var/ossec/bin/wazuh-logtest < testes/vereditos-exemplo.txt
   ```

   Resultado esperado, uma linha de cada veredito: `id: '100501'` nível 3, `100502` nível 7, `100510`, `100511` e `100512` nível 12. O `wazuh-logtest` só testa decodificação e regras; ele não executa a *active response*.

## Verificação em operação

```bash
grep -E '"id":"1005(0[0-9]|1[0-9])"' /var/ossec/logs/alerts/alerts.json | tail -n 5
/var/ossec/bin/agent_control -l
```

No *dashboard*, filtro `rule.groups: mecanismo`.
