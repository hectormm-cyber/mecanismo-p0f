#!/usr/bin/env python3
"""prober.py v6: sondagem ativa (nmap -sT), leitura do p0f e alertas.

v6: o registro ganha "mecanismo" (identifica a origem para as regras do Wazuh)
e "srcip" (copia do ip, campo que as active responses do Wazuh usam para bloquear).

Fluxo: evento do detector (events.jsonl) -> ping (TTL) -> nmap -sT nas portas comuns
-> leitura das linhas syn+ack do p0f.log para o IP -> comparacao com o baseline
(SO, portas, saltos, DHCP Class-Id) -> veredito em verdicts.jsonl e, quando nao
estiver tudo ok, alerta em alerts.jsonl.

Regra central: um MAC autorizado (inteiro ou pelo prefixo) so e consistente se o
equipamento tambem se comporta como o baseline. Divergencia de SO, portas, saltos ou
Class-Id, ou ausencia total de resposta onde o baseline exige portas, vira alerta.
"""
import argparse, collections, json, os, re, subprocess, time

EVENTS   = "/var/log/mecanismo/events.jsonl"
P0F_LOG  = "/var/log/p0f/p0f.log"
OUT      = "/var/log/mecanismo/verdicts.jsonl"
ALERTS   = "/var/log/mecanismo/alerts.jsonl"
BASELINE = "/opt/mecanismo/baseline.json"
PORTS    = "22,80,135,139,443,445,515,554,631,3389,8080,9100"
COOLDOWN = 300  # segundos sem sondar o mesmo par (IP, MAC) de novo

FAMILIES = ["Windows", "Linux", "Mac OS X", "iOS", "Android",
            "FreeBSD", "OpenBSD", "NetBSD", "Solaris"]
UNIX_LIKE = ["linux", "mac", "ios", "android", "bsd", "solaris", "unix"]
ALERT_VERDICTS = {"mismatch-possible-clone", "unauthorized-fingerprinted",
                  "unauthorized-unresolved"}
MISSING = object()  # Class-Id desconhecido (ex.: modo manual sem evento)


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_baseline():
    """Le o baseline a cada sondagem, assim edicoes no arquivo valem sem reiniciar."""
    try:
        with open(BASELINE) as fh:
            return {k.lower().rstrip("*").rstrip(":"): v
                    for k, v in json.load(fh).items()}
    except (OSError, ValueError):
        return {}


def base_for(mac):
    """Entrada do baseline para o MAC: exata ou, sem ela, pelo prefixo (OUI)."""
    if not mac:
        return {}
    b = load_baseline()
    mac = mac.lower()
    return b.get(mac) or b.get(mac[:8]) or {}


def event_for(ip):
    """Evento mais recente do detector para este IP, ou None."""
    last = None
    try:
        with open(EVENTS) as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("ip") == ip and ev.get("mac"):
                    last = ev
    except OSError:
        pass
    return last


def icmp_ttl(ip):
    """TTL observado na resposta ao ping, ou None."""
    try:
        r = subprocess.run(["ping", "-c", "2", "-W", "3", ip],
                           capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return None
    m = re.search(r"ttl=(\d+)", r.stdout)
    return int(m.group(1)) if m else None


def ttl_family(ttl):
    for base in (64, 128, 255):
        if ttl <= base:
            return {64: "Unix-like", 128: "Windows", 255: "Network device"}[base]
    return None


def ttl_dist(ttl):
    """Saltos estimados: menor TTL inicial comum (64, 128, 255) menos o TTL observado."""
    for base in (64, 128, 255):
        if ttl <= base:
            return base - ttl
    return None


def scan(ip):
    """Conexao completa (nmap -sT). Devolve a lista de portas abertas."""
    cmd = ["nmap", "-sT", "-Pn", "-n", "-p", PORTS, "--open",
           "--max-retries", "1", "--max-rtt-timeout", "3s",
           "--host-timeout", "90s", "-oG", "-", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=150)
    except subprocess.TimeoutExpired:
        return []
    return [int(p) for p in re.findall(r"(\d+)/open/tcp", r.stdout)]


def p0f_fields(line):
    """Converte '[data] mod=...|cli=...|...' em dicionario."""
    if "mod=" not in line:
        return None
    body = line.split("] ", 1)[-1].strip()
    return dict(kv.split("=", 1) for kv in body.split("|") if "=" in kv)


def p0f_synack(ip, offset):
    """Linhas syn+ack com subj=srv do IP-alvo gravadas depois de 'offset'."""
    time.sleep(2)  # tempo para o p0f gravar
    found = []
    try:
        with open(P0F_LOG) as fh:
            fh.seek(offset)
            for line in fh:
                f = p0f_fields(line)
                if (f and f.get("mod") == "syn+ack" and f.get("subj") == "srv"
                        and f.get("srv", "").split("/")[0] == ip):
                    found.append(f)
    except FileNotFoundError:
        pass
    return found


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


def decide(status, expected_os, observed, open_ports, dist, base, class_id=MISSING):
    """Devolve (veredito, motivos). Pura: nao acessa rede nem arquivos."""
    reasons = []
    if status != "authorized":
        return ("unauthorized-fingerprinted" if observed else "unauthorized-unresolved"), reasons

    # 1) portas: o baseline diz quais devem estar abertas para o mecanismo
    exp_ports = base.get("ports")
    if exp_ports is not None:
        missing = sorted(set(exp_ports) - set(open_ports))
        extra = sorted(set(open_ports) - set(exp_ports))
        if missing:
            reasons.append("portas-ausentes:%s" % ",".join(map(str, missing)))
        if extra:
            reasons.append("portas-extras:%s" % ",".join(map(str, extra)))

    # 2) DHCP Class-Id (so quando o evento trouxe a informacao)
    exp_class = base.get("class_id")
    if exp_class and class_id is not MISSING and class_id != exp_class:
        reasons.append("dhcp-class-id:esperado=%s,observado=%s" % (exp_class, class_id))

    # 3) sem fingerprint: com divergencia de portas ou Class-Id e alerta
    if not observed:
        if reasons:
            reasons.append("sem-fingerprint")
            return "mismatch-possible-clone", reasons
        return "inconclusive", reasons

    # 4) SO e saltos
    if expected_os and not same_family(expected_os, observed):
        reasons.append("os:esperado=%s,observado=%s" % (expected_os, observed))
    exp_dist = to_int(base.get("dist"))
    if exp_dist is not None and dist is not None and dist != exp_dist:
        reasons.append("saltos:esperado=%d,observado=%d" % (exp_dist, dist))

    return ("mismatch-possible-clone" if reasons else "consistent"), reasons


def probe(ip, mac=None, status="unknown", expected=None, name=None, base=None,
          class_id=MISSING, hostname=None, event=None):
    base = base or {}
    event = event or {}
    ttl = icmp_ttl(ip)
    offset = os.path.getsize(P0F_LOG) if os.path.exists(P0F_LOG) else 0
    ports = scan(ip)
    syn = p0f_synack(ip, offset)
    if ttl is None:  # host ainda configurando a pilha no instante do ACK
        ttl = icmp_ttl(ip)

    os_name = observed = method = raw_sig = None
    dist = None
    if syn:
        os_name = collections.Counter(f.get("os", "???") for f in syn).most_common(1)[0][0]
        raw_sig, dist = syn[0].get("raw_sig"), to_int(syn[0].get("dist"))
        observed, method = os_family(os_name), "p0f"
    if observed is None and ttl:
        observed = ttl_family(ttl)
        method = (method + "+icmp-ttl") if method else "icmp-ttl"
    if dist is None and ttl:
        dist = ttl_dist(ttl)
    if method is None:
        method = "none"

    verdict, reasons = decide(status, expected, observed, ports, dist, base, class_id)
    alert = verdict in ALERT_VERDICTS

    rec = {"ts": utcnow(), "mecanismo": "modo1", "ip": ip, "srcip": ip,
           "mac": mac, "name": name, "status": status,
           "hostname": hostname,
           "dhcp_class_id": None if class_id is MISSING else class_id,
           "expected_os": expected, "expected_ports": base.get("ports"),
           "expected_dist": base.get("dist"), "icmp_ttl": ttl, "open_ports": ports,
           "p0f_os": os_name, "dist": dist, "raw_sig": raw_sig,
           "observed_family": observed, "method": method,
           "verdict": verdict, "reasons": reasons, "alert": alert,
           "event_ts": event.get("ts"), "event_rx_ts": event.get("rx_ts"),
           "event_source": event.get("source", "dhcp"), "static": event.get("static"),
           "ip_prev_mac": event.get("ip_prev_mac"),
           "dhcp_param_list": event.get("param_list")}
    with open(OUT, "a") as o:
        o.write(json.dumps(rec) + "\n")
    if alert:
        with open(ALERTS, "a") as o:
            o.write(json.dumps(rec) + "\n")
        print("ALERTA [%s] %s %s %s" % (verdict, ip, mac, ";".join(reasons)), flush=True)
    print(json.dumps(rec), flush=True)
    return rec


def follow(from_start):
    created = not os.path.exists(EVENTS)
    while not os.path.exists(EVENTS):
        time.sleep(1)
    f = open(EVENTS)
    if not from_start and not created:  # arquivo novo: le desde o inicio
        f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", help="sonda um IP uma vez e sai")
    ap.add_argument("--mac", help="com --ip: usa a entrada desse MAC no baseline")
    ap.add_argument("--expected", help="com --ip: SO esperado (trata o IP como authorized)")
    ap.add_argument("--from-start", action="store_true",
                    help="processa o events.jsonl desde o inicio")
    ap.add_argument("--probe-authorized", action="store_true",
                    help="tambem sonda os authorized (valida SO, portas, saltos e Class-Id)")
    a = ap.parse_args()

    if a.ip:
        ev = event_for(a.ip)
        mac = a.mac.lower() if a.mac else (((ev or {}).get("mac") or "").lower() or None)
        base = base_for(mac)
        class_id, hostname = MISSING, None
        if ev and (ev.get("mac") or "").lower() == mac:
            class_id, hostname = (ev.get("class_id") if ev.get("source", "dhcp") != "arp" else MISSING), ev.get("hostname")
        expected = a.expected or base.get("os")
        status = "authorized" if (expected or base) else "unknown"
        probe(a.ip, mac=mac, status=status, expected=expected,
              name=base.get("name"), base=base, class_id=class_id, hostname=hostname,
              event=ev if ev and (ev.get("mac") or "").lower() == mac else None)
        return

    last = {}
    for ev in follow(a.from_start):
        ip, st, mac = ev.get("ip"), ev.get("status"), (ev.get("mac") or "").lower()
        if not ip or (st == "authorized" and not a.probe_authorized):
            continue
        key = (ip, mac)
        if time.time() - last.get(key, 0) < COOLDOWN:
            continue
        last[key] = time.time()
        base = base_for(mac)
        probe(ip, mac=mac, status=st,
              expected=ev.get("expected_os") or base.get("os"),
              name=ev.get("name"), base=base,
              class_id=(ev.get("class_id") if ev.get("source", "dhcp") != "arp" else MISSING),
              hostname=ev.get("hostname"), event=ev)


if __name__ == "__main__":
    main()
