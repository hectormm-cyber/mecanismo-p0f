
#!/usr/bin/env python3

"""sensor.py (Modo 2): coleta passiva na ponte da filial.

 

Roda no MecanismoP0f-Inspecao, inline entre o SwitchFilial e o MikrotikFilial.

Nao decide nada: apenas observa e grava eventos no mesmo formato do

events.jsonl do Modo 1. A classificacao e o veredito ficam no analyzer.py,

no servidor da matriz (decisao centralizada).

 

Duas fontes, as duas passivas:

  1. tcpdump na br0, filtrando ARP e DHCP. Da o par (MAC, IP), o Host-Name e

     o Class-Id. E a deteccao de presenca.

  2. p0f.log, linhas mod=syn com subj=cli. Da o fingerprint da pilha TCP do

     host (os, dist, raw_sig). O p0f nao registra MAC, por isso o IP e

     correlacionado com o mapa montado pela fonte 1.

 

Diferenca para o Modo 1: nada e sondado. O host e caracterizado pelo SYN que

ele proprio envia, sem que o mecanismo gere um unico pacote.

"""

import json, os, re, socket, subprocess, sys, threading, time

 

IFACE  = "br0"

P0F    = "/var/log/p0f/p0f.log"

OUT    = "/var/log/mecanismo/events.jsonl"

SITE   = socket.gethostname()

BPF    = "arp or (udp port 67 or udp port 68)"

ABSENT = 600   # segundos fora de vista antes de reanunciar o mesmo par

 

# --- ARP (tcpdump -e, uma linha por pacote) ---------------------------------

# 00:50:79:66:68:06 > ff:ff:..., ethertype ARP (0x0806), ...: Request who-has

# 10.1.0.1 tell 10.1.0.198, length 46

ARP_SRC  = re.compile(r"^\d+:\d+:\d+\.\d+\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+>")

ARP_TELL = re.compile(r"tell (\d+\.\d+\.\d+\.\d+)")

ARP_ISAT = re.compile(r"reply (\d+\.\d+\.\d+\.\d+) is-at ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})")

 

# --- DHCP (tcpdump -v, varias linhas por pacote) ----------------------------

DHCP_HDR  = re.compile(r"BOOTP/DHCP, (\w+) from ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})")

DHCP_CEA  = re.compile(r"Client-Ethernet-Address ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})")

DHCP_HOST = re.compile(r'Hostname (?:Option 12|\(12\)), length \d+: "([^"]*)"')

DHCP_CLS  = re.compile(r'Vendor-Class (?:Option 60|\(60\)), length \d+: "([^"]*)"')

DHCP_YIP  = re.compile(r"Your-IP (\d+\.\d+\.\d+\.\d+)")

DHCP_CIP  = re.compile(r"Client-IP (\d+\.\d+\.\d+\.\d+)")

DHCP_RIP  = re.compile(r"Requested-IP (?:Option 50|\(50\)), length \d+: (\d+\.\d+\.\d+\.\d+)")
DHCP_TYPE = re.compile(r"DHCP-Message (?:Option 53|\(53\)), length \d+: (\w+)")

NEW_PKT   = re.compile(r"^\d+:\d+:\d+\.\d+ ")

 

lock    = threading.Lock()

ip_mac  = {}   # ip -> mac, montado pelo ARP e pelo DHCP

seen    = {}   # (mac, ip) -> instante do ultimo anuncio

meta    = {}   # mac -> {"hostname": ..., "class_id": ...}

 

 

def utcnow():

    """Mesmo formato de ts do Modo 1, no relogio do servidor."""

    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())

 

 

def emit(ev):

    ev.setdefault("ts", utcnow())

    ev.setdefault("site", SITE)

    ev.setdefault("mode", "2")

    with lock:

        with open(OUT, "a") as fh:

            fh.write(json.dumps(ev) + "\n")

    print(json.dumps(ev), flush=True)

 

 

def presence(mac, ip, source, force=False):

    """Anuncia um par (MAC, IP) novo, ou um que voltou depois de ABSENT."""

    if not mac or not ip or ip == "0.0.0.0":

        return

    now = time.time()

    with lock:

        prev = ip_mac.get(ip)

        ip_mac[ip] = mac

        last = seen.get((mac, ip))

        seen[(mac, ip)] = now

        info = dict(meta.get(mac, {}))

    if not force and last is not None and now - last <= ABSENT:

        return

    emit({"mac": mac, "ip": ip, "kind": "presence", "source": source,

          "hostname": info.get("hostname"), "class_id": info.get("class_id"),

          "ip_prev_mac": prev if prev and prev != mac else None})

 

 

# --- fonte 1: ARP e DHCP na ponte -------------------------------------------

 

def watch_link():

    cmd = ["tcpdump", "-i", IFACE, "-l", "-n", "-e", "-v", "-s", "0", BPF]

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,

                         text=True, bufsize=1)

    cur = {}

    for line in p.stdout:

        line = line.rstrip()

        low = line.lower()

 

        # cabecalho de pacote novo: fecha o registro DHCP anterior

        if NEW_PKT.match(line) and cur:

            flush_dhcp(cur)

            cur = {}

 

        # --- ARP ---

        if "ethertype ARP" in line or " arp " in low:

            m, t = ARP_SRC.match(low), ARP_TELL.search(low)

            if m and t:

                presence(m.group(1), t.group(1), "bridge-arp")

            r = ARP_ISAT.search(low)

            if r:

                presence(r.group(2), r.group(1), "bridge-arp")

            continue

 

        # --- DHCP ---

        h = DHCP_HDR.search(line)

        if h:

            cur = {"mac": h.group(2).lower(), "msg": h.group(1).lower()}

            continue

        if not cur:

            continue

        for rx, key in ((DHCP_CEA, "mac"), (DHCP_HOST, "hostname"),

                        (DHCP_CLS, "class_id"), (DHCP_YIP, "ip"),

                        (DHCP_CIP, "cip"), (DHCP_RIP, "rip"), (DHCP_TYPE, "dtype")):

            m = rx.search(line)

            if m:

                cur[key] = m.group(1).lower() if key == "mac" else m.group(1)

    if cur:

        flush_dhcp(cur)

 

 

def flush_dhcp(cur):

    mac = cur.get("mac")

    if not mac:

        return

    if (cur.get("dtype") or "").lower() not in ("discover", "request"):
        return  # Release/Inform/Decline nao trazem Class-Id confiavel
    with lock:

        info = meta.setdefault(mac, {})

        if cur.get("hostname"):

            info["hostname"] = cur["hostname"]

        if cur.get("class_id"):

            info["class_id"] = cur["class_id"]

    ip = cur.get("ip") or cur.get("cip") or cur.get("rip")

    if ip and ip != "0.0.0.0":

        presence(mac, ip, "bridge-dhcp", force=True)

 

 

# --- fonte 2: p0f ------------------------------------------------------------

 

def p0f_fields(line):

    if "mod=" not in line:

        return None

    body = line.split("] ", 1)[-1].strip()

    return dict(kv.split("=", 1) for kv in body.split("|") if "=" in kv)

 

 

def watch_p0f():

    while not os.path.exists(P0F):

        time.sleep(1)

    fh = open(P0F)

    fh.seek(0, os.SEEK_END)

    last = {}

    while True:

        line = fh.readline()

        if not line:

            time.sleep(0.5)

            continue

        f = p0f_fields(line)

        if not f or f.get("subj") != "cli":

            continue

        ip = (f.get("cli") or "").split("/")[0]

        if not ip:

            continue

        with lock:

            mac = ip_mac.get(ip)

            info = dict(meta.get(mac, {})) if mac else {}

        if not mac:

            continue  # sem MAC nao da para consultar o baseline

        mod = f.get("mod")

        key = (mac, ip, mod, f.get("raw_sig") or f.get("raw_mtu")
               or f.get("raw_freq"))
        if time.time() - last.get(key, 0) < 300:
            continue
        last[key] = time.time()
        if mod == "syn":
            emit({"mac": mac, "ip": ip, "kind": "fingerprint",

                  "source": "bridge-syn",

                  "hostname": info.get("hostname"),

                  "class_id": info.get("class_id"),

                  "p0f_os": f.get("os"), "dist": f.get("dist"),

                  "raw_sig": f.get("raw_sig"), "params": f.get("params")})

        elif mod == "uptime":

            emit({"mac": mac, "ip": ip, "kind": "uptime",

                  "source": "bridge-uptime",

                  "uptime": f.get("uptime"), "raw_freq": f.get("raw_freq")})

        elif mod == "mtu":

            emit({"mac": mac, "ip": ip, "kind": "mtu", "source": "bridge-mtu",

                  "link": f.get("link"), "raw_mtu": f.get("raw_mtu")})

 

 

def main():

    os.makedirs(os.path.dirname(OUT), exist_ok=True)

    for fn in (watch_link, watch_p0f):

        threading.Thread(target=fn, daemon=True).start()

    try:

        while True:

            time.sleep(3600)

    except KeyboardInterrupt:

        sys.exit(0)

 

 

if __name__ == "__main__":

    main()

