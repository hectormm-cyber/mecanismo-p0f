#!/usr/bin/env python3
"""Aplica ao ossec.conf do manager os trechos de trechos/ossec-manager.xml.

- Cada <white_list> do trecho entra no fim do bloco <global>, se ainda nao existir.
- Os blocos <active-response> do trecho entram antes do ultimo </ossec_config>,
  entre marcadores; se os marcadores ja existirem, o conteudo entre eles e trocado.
- Antes de gravar, guarda uma copia em ossec.conf.antes-mecanismo (so na primeira vez).

Uso: python3 aplicar_trechos.py [--conf /var/ossec/etc/ossec.conf] [--dry-run]
"""
import argparse, os, re, shutil

AQUI = os.path.dirname(os.path.abspath(__file__))
TRECHO = os.path.join(AQUI, "trechos", "ossec-manager.xml")
INICIO = "  <!-- mecanismo-modo1: inicio (gerado por aplicar_trechos.py) -->"
FIM = "  <!-- mecanismo-modo1: fim -->"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", default="/var/ossec/etc/ossec.conf")
    ap.add_argument("--dry-run", action="store_true", help="mostra o resultado sem gravar")
    a = ap.parse_args()

    trecho = re.sub(r"<!--.*?-->", "", open(TRECHO).read(), flags=re.S)
    wl = re.findall(r"<white_list>.*?</white_list>", trecho)
    ar = re.findall(r"<active-response>.*?</active-response>", trecho, flags=re.S)
    conf = open(a.conf).read()

    # 1) lista branca dentro do primeiro <global>
    g = re.search(r"<global>.*?</global>", conf, flags=re.S)
    if not g:
        raise SystemExit("bloco <global> nao encontrado em %s" % a.conf)
    novos = [w for w in wl if w not in g.group(0)]
    if novos:
        fim_global = g.end() - len("</global>")
        conf = (conf[:fim_global] + "".join("  %s\n  " % w for w in novos)
                + conf[fim_global:])

    # 2) active responses entre marcadores, antes do ultimo </ossec_config>
    bloco = INICIO + "\n" + "\n\n".join(
        "  " + b.replace("\n", "\n  ") for b in ar) + "\n" + FIM + "\n"
    if INICIO in conf:
        conf = re.sub(re.escape(INICIO) + r".*?" + re.escape(FIM) + r"\n?",
                      lambda m: bloco, conf, flags=re.S)
    else:
        pos = conf.rfind("</ossec_config>")
        if pos < 0:
            raise SystemExit("</ossec_config> nao encontrado em %s" % a.conf)
        conf = conf[:pos] + bloco + "\n" + conf[pos:]

    if a.dry_run:
        print(conf)
        return
    copia = a.conf + ".antes-mecanismo"
    if not os.path.exists(copia):
        shutil.copy2(a.conf, copia)
    with open(a.conf, "w") as f:
        f.write(conf)
    print("lista branca acrescentada: %s" % (", ".join(novos) or "nenhuma (ja existia)"))
    print("active responses: %d bloco(s) entre os marcadores mecanismo-modo1" % len(ar))
    print("copia original: %s" % copia)


if __name__ == "__main__":
    main()
