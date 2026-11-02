
#!/usr/bin/env python3

"""analyzer.py (Modo 2): decisao centralizada na matriz.

 

Le os eventos que o sensor.py da filial envia pelo tunel (rsyslog), consulta o

mesmo baseline.json do Modo 1 e aplica a funcao decide(). Grava o veredito em

verdicts.jsonl e, quando houver alerta, tambem em alerts.jsonl, nos mesmos

caminhos e com os mesmos campos do Modo 1, acrescidos de "mode": "2".

 

A decisao fica aqui, e nao na filial, para que a funcao de decisao e o baseline

sejam identicos nos dois modos. Assim qualquer diferenca de resultado vem da

camada de coleta, que e o que o trabalho compara.

 

Fatores do Modo 2 (ver baseline.json):

  MAC/OUI  : chave do baseline, lida do quadro Ethernet na ponte

  dist     : deve ser 0, porque a ponte esta no mesmo segmento do host

  class_id : Class-Id do DHCP capturado na ponte

  os       : familia observada pelo p0f no SYN espontaneo do host

  raw_sig  : assinatura estrutural da pilha TCP, ignorando o octeto de TTL

"""

import argparse, glob, json, os, time

 

EVENTS   = "/var/log/filiais"          # um subdiretorio por filial

OUT      = "/var/log/mecanismo/verdicts.jsonl"

ALERTS   = "/var/log/mecanismo/alerts.jsonl"

BASELINE = "/opt/mecanismo/baseline_2.json"

COOLDOWN = 300   # segundos sem reavaliar o mesmo par (MAC, IP)

GRACE    = 120   # segundos de espera por um fingerprint antes de decidir

 

FAMILIES  = ["Windows", "Linux", "Mac OS X", "iOS", "Android",

             "FreeBSD", "OpenBSD", "NetBSD", "Solaris"]

UNIX_LIKE = ["linux", "mac", "ios", "android", "bsd", "solaris", "unix"]

ALERT_VERDICTS = {"mismatch-possible-clone", "unauthorized-fingerprinted",

                  "unauthorized-unresolved"}

MISSING = object()

 

 

def utcnow():

    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

 

 

def load_baseline():

    """Lido a cada veredito, para que edicoes valham sem reiniciar o servico."""

    try:

        with open(BASELINE) as fh:

            return {k.lower().rstrip("*").rstrip(":"): v

                    for k, v in json.load(fh).items()}

    except (OSError, ValueError):

        return {}

 

 

def lookup(mac):

    """Entrada exata do MAC; sem ela, a do prefixo (OUI). Igual ao Modo 1."""

    if not mac:

        return {}, None

    b = load_baseline()

    mac = mac.lower()

    if mac in b:

        return b[mac], "mac"

    if mac[:8] in b:

        return b[mac[:8]], "oui"

    return {}, None

 

 

def sig_core(raw_sig):

    """Parte estrutural da assinatura do p0f, sem o campo de TTL e saltos.

 

    raw_sig = ver:ittl+dist:olen:mss:wsize,scale:olayout:quirks:pclass

    O campo 1 carrega o TTL, que o invasor altera com ip_default_ttl, e os

    saltos, ja verificados por dist. Os demais campos descrevem a pilha: MSS,

    janela, escala, ordem das opcoes TCP e quirks de cabecalho.

    """

    if not raw_sig:

        return None

    p = raw_sig.split(":")

    if len(p) < 8:

        return None

    return ":".join([p[0]] + p[2:])

 

 

def os_family(name):

    if not name or "?" in name:

        return None

    for fam in FAMILIES:

        if fam.lower() in name.lower():

            return fam

    return name

 

 

def same_family(expected, observed):

    e, o = expected.lower(), observed.lower()

    if e in o or o in e:

        return True

    return o == "unix-like" and any(k in e for k in UNIX_LIKE)

 

 

def to_int(value):

    try:

        return int(value)

    except (TypeError, ValueError):

        return None

 

 

def decide(status, base, observed, dist, raw_sig, class_id=MISSING):

    """Devolve (veredito, motivos). Pura: nao acessa rede nem arquivos."""

    reasons = []

    if status != "authorized":

        return ("unauthorized-fingerprinted" if observed

                else "unauthorized-unresolved"), reasons

 

    # 1) saltos: na ponte, um host da LAN tem de estar a 0 saltos

    exp_dist = to_int(base.get("dist"))

    obs_dist = to_int(dist)

    if exp_dist is not None and obs_dist is not None and obs_dist != exp_dist:

        reasons.append("saltos:esperado=%d,observado=%d" % (exp_dist, obs_dist))

 

    # 2) Class-Id do DHCP, quando o evento o trouxe

    exp_class = base.get("class_id")

    if exp_class and class_id is not MISSING and class_id != exp_class:

        reasons.append("dhcp-class-id:esperado=%s,observado=%s"

                       % (exp_class, class_id))

 

    # 3) sem fingerprint: com divergencia acumulada e alerta

    if not observed and not raw_sig:

        if reasons:

            reasons.append("sem-fingerprint")

            return "mismatch-possible-clone", reasons

        return "inconclusive", reasons

 

    # 4) familia de SO

    exp_os = base.get("os")

    if exp_os and observed and not same_family(exp_os, observed):

        reasons.append("os:esperado=%s,observado=%s" % (exp_os, observed))

 

    # 5) assinatura estrutural da pilha TCP (o fator novo do Modo 2)

    exp_sig = base.get("raw_sig")
    if exp_sig and raw_sig:
        exp_list = exp_sig if isinstance(exp_sig, list) else [exp_sig]
        if base.get("sig_tolerance") == "ignore_ttl":
            e_set = {sig_core(x) for x in exp_list} - {None}
            o = sig_core(raw_sig)
        else:
            e_set = set(exp_list)
            o = raw_sig
        if e_set and o and o not in e_set:
            reasons.append("raw-sig:esperado=%s,observado=%s"
                           % ("|".join(sorted(e_set)), o))

 

    return ("mismatch-possible-clone" if reasons else "consistent"), reasons

 

 

class State:

    """Observacoes acumuladas por par (MAC, IP) ate o veredito."""

 

    def __init__(self):

        self.d = {}

 

    def update(self, ev):

        mac = (ev.get("mac") or "").lower()

        ip = ev.get("ip")

        if not mac or not ip:

            return None

        s = self.d.setdefault((mac, ip), {

            "first": time.time(), "last_verdict": 0, "site": ev.get("site"),

            "hostname": None, "class_id": MISSING, "p0f_os": None,

            "dist": None, "raw_sig": None, "link": None, "uptime": None,

            "sources": set(), "ip_prev_mac": None})

        before = (s["class_id"], s["raw_sig"], s["dist"], s["p0f_os"])
        s["sources"].add(ev.get("source"))

        for k in ("hostname", "p0f_os", "dist", "raw_sig", "link", "uptime",

                  "ip_prev_mac"):

            if ev.get(k) is not None:

                s[k] = ev[k]

        if "class_id" in ev and ev.get("source", "").startswith("bridge-dhcp"):

            s["class_id"] = ev.get("class_id")

        elif s["class_id"] is MISSING and ev.get("class_id") is not None:

            s["class_id"] = ev.get("class_id")

        if (s["class_id"], s["raw_sig"], s["dist"], s["p0f_os"]) != before:
            s["dirty"] = True
        return (mac, ip)

 

 

def verdict(mac, ip, s):

    base, match = lookup(mac)

    status = "authorized" if base else "unknown"

    observed = os_family(s.get("p0f_os"))

    v, reasons = decide(status, base, observed, s.get("dist"),

                        s.get("raw_sig"), s.get("class_id"))

    alert = v in ALERT_VERDICTS

    rec = {"ts": utcnow(), "mode": "2", "site": s.get("site"),

           "ip": ip, "mac": mac, "name": base.get("name"), "status": status,

           "match": match, "hostname": s.get("hostname"),

           "dhcp_class_id": None if s.get("class_id") is MISSING else s.get("class_id"),

           "expected_os": base.get("os"), "expected_dist": base.get("dist"),

           "expected_sig": base.get("raw_sig"),

           "p0f_os": s.get("p0f_os"), "dist": s.get("dist"),

           "raw_sig": s.get("raw_sig"), "sig_core": sig_core(s.get("raw_sig")),

           "link": s.get("link"), "uptime": s.get("uptime"),

           "observed_family": observed,

           "method": "p0f-passive" if s.get("raw_sig") else "none",

           "sources": sorted(x for x in s.get("sources") if x),

           "ip_prev_mac": s.get("ip_prev_mac"),

           "verdict": v, "reasons": reasons, "alert": alert}

    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    with open(OUT, "a") as fh:

        fh.write(json.dumps(rec) + "\n")

    if alert:

        with open(ALERTS, "a") as fh:

            fh.write(json.dumps(rec) + "\n")

        print("ALERTA [%s] %s %s %s" % (v, ip, mac, ";".join(reasons)), flush=True)

    print(json.dumps(rec), flush=True)

    return rec

 

 

def follow(paths, from_start):

    """Segue todos os events.jsonl recebidos das filiais."""

    handles = {}

    while True:

        for path in glob.glob(paths):

            if path not in handles:

                fh = open(path)

                if not from_start:

                    fh.seek(0, os.SEEK_END)

                handles[path] = fh

        got = False

        for fh in list(handles.values()):

            while True:

                line = fh.readline()

                if not line:

                    break

                got = True

                try:

                    yield json.loads(line)

                except ValueError:

                    continue

        if not got:

            yield None

            time.sleep(0.5)

 

 

def main():

    ap = argparse.ArgumentParser()

    ap.add_argument("--from-start", action="store_true",

                    help="processa os eventos recebidos desde o inicio")

    ap.add_argument("--once", action="store_true",

                    help="processa o que ja chegou, decide e sai")

    a = ap.parse_args()

 

    st = State()

    pending = {}

    pattern = os.path.join(EVENTS, "*", "events.jsonl")

 

    for ev in follow(pattern, a.from_start or a.once):

        now = time.time()

        if ev is not None:

            key = st.update(ev)

            if key:

                pending[key] = now

        elif a.once:

            for key in list(pending):

                verdict(key[0], key[1], st.d[key])

            return

 

        if a.once:
            continue  # no --once decide so no final
        # decide quando ha fingerprint, ou quando a espera acabou

        for key in list(pending):

            s = st.d[key]

            ready = s.get("raw_sig") or (now - s["first"] >= GRACE)

            if not ready:

                continue

            if now - s["last_verdict"] < COOLDOWN and not s.get("dirty"):

                pending.pop(key, None)

                continue

            s["dirty"] = False
            s["last_verdict"] = now

            pending.pop(key, None)

            verdict(key[0], key[1], s)

 

 

if __name__ == "__main__":

    main()

