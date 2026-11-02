#!/usr/bin/env python3
"""Aplica ao ossec.conf os trechos da integracao do mecanismo com o Wazuh.

  aplicar_trechos.py manager   no WazuhServer: lista branca e active responses
  aplicar_trechos.py agente    no MecanismoP0f: leitura do verdicts.jsonl e
                               active response desligada neste agente

Regras de edicao, iguais nos dois casos:
- blocos novos entram antes do ultimo </ossec_config>, entre marcadores; rodar de
  novo troca o conteudo entre os marcadores, sem duplicar;
- manager: cada <white_list> entra no fim do bloco <global>, se ainda nao existir;
- agente: o <disabled> do bloco <active-response> existente passa a yes;
- antes de gravar, guarda ossec.conf.antes-mecanismo (so na primeira vez).

Uso: python3 aplicar_trechos.py manager|agente [--conf CAMINHO] [--dry-run]
"""
import argparse, os, re, shutil

AQUI = os.path.dirname(os.path.abspath(__file__))
TRECHOS = {
    "manager": os.path.join(AQUI, "manager", "trechos", "ossec-manager.xml"),
    "agente": os.path.join(AQUI, "agente-mecanismo", "trechos", "ossec-agente-mecanismo.xml"),
}
INICIO = "  <!-- mecanismo-p0f: inicio (gerado por aplicar_trechos.py) -->"
FIM = "  <!-- mecanismo-p0f: fim -->"


def blocos(texto, tag):
    return re.findall(r"<%s>.*?</%s>" % (tag, tag), texto, flags=re.S)


def entre_marcadores(conf, novos):
    """Coloca os blocos entre os marcadores, antes do ultimo </ossec_config>."""
    bloco = INICIO + "\n" + "\n\n".join(
        "  " + b.replace("\n", "\n  ") for b in novos) + "\n" + FIM + "\n"
    if INICIO in conf:
        return re.sub(re.escape(INICIO) + r".*?" + re.escape(FIM) + r"\n?",
                      lambda m: bloco, conf, flags=re.S)
    pos = conf.rfind("</ossec_config>")
    if pos < 0:
        raise SystemExit("</ossec_config> nao encontrado")
    return conf[:pos] + bloco + "\n" + conf[pos:]


def manager(conf, trecho, log):
    g = re.search(r"<global>.*?</global>", conf, flags=re.S)
    if not g:
        raise SystemExit("bloco <global> nao encontrado")
    novos = [w for w in blocos(trecho, "white_list") if w not in g.group(0)]
    if novos:
        fim = g.end() - len("</global>")
        conf = conf[:fim] + "".join("  %s\n  " % w for w in novos) + conf[fim:]
    log.append("lista branca acrescentada: %s" % (", ".join(novos) or "nenhuma (ja existia)"))
    ar = blocos(trecho, "active-response")
    log.append("active responses entre os marcadores: %d" % len(ar))
    return entre_marcadores(conf, ar)


def agente(conf, trecho, log):
    lf = blocos(trecho, "localfile")
    sem_marcadores = re.sub(re.escape(INICIO) + r".*?" + re.escape(FIM), "", conf, flags=re.S)
    existentes = [b for b in blocos(sem_marcadores, "active-response")]
    if existentes:
        alvo = existentes[0]
        if re.search(r"<disabled>\s*\w+\s*</disabled>", alvo):
            novo = re.sub(r"<disabled>\s*\w+\s*</disabled>", "<disabled>yes</disabled>", alvo, count=1)
        else:
            novo = alvo.replace("<active-response>", "<active-response>\n    <disabled>yes</disabled>", 1)
        conf = conf.replace(alvo, novo, 1)
        log.append("active response do agente: <disabled>yes</disabled> no bloco existente")
        conf = entre_marcadores(conf, lf)
    else:
        conf = entre_marcadores(conf, lf + blocos(trecho, "active-response"))
        log.append("active response do agente: bloco novo com <disabled>yes</disabled>")
    log.append("localfile entre os marcadores: %d" % len(lf))
    return conf


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("alvo", choices=sorted(TRECHOS))
    ap.add_argument("--conf", default="/var/ossec/etc/ossec.conf")
    ap.add_argument("--dry-run", action="store_true", help="mostra o resultado sem gravar")
    a = ap.parse_args()

    trecho = re.sub(r"<!--.*?-->", "", open(TRECHOS[a.alvo]).read(), flags=re.S)
    conf, log = open(a.conf).read(), []
    conf = (manager if a.alvo == "manager" else agente)(conf, trecho, log)

    if a.dry_run:
        print(conf)
        return
    copia = a.conf + ".antes-mecanismo"
    if not os.path.exists(copia):
        shutil.copy2(a.conf, copia)
    with open(a.conf, "w") as f:
        f.write(conf)
    print("\n".join(log))
    print("copia original: %s" % copia)


if __name__ == "__main__":
    main()
