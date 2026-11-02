#!/usr/bin/env python3
"""Polling ARP e DHCP (Modo 1): le a tabela ARP e os leases DHCP do MikrotikFilial
por SSH e grava cada par (MAC, IP) novo no mesmo events.jsonl do detector.

Complementa o detector.py nos dois casos que o log DHCP nao cobre: dispositivo com
IP estatico que nao envia nem inform, e mensagem Syslog perdida (UDP). Os eventos
tem os mesmos campos do detector, entao o prober.py os sonda sem alteracao."""
import argparse, ipaddress, json, os, re, subprocess, time

ROUTER     = "10.1.0.1"                       # MikrotikFilial (CHR-FILIAL)
USER       = "monitor"                        # usuario somente leitura no RouterOS
KEY        = "/root/.ssh/mecanismo_rsa"       # chave privada do servidor
LAN        = ipaddress.ip_network("10.1.0.0/24")
BASE       = "/opt/mecanismo/baseline.json"
OUT        = "/var/log/mecanismo/events.jsonl"
INTERVAL   = 60     # segundos entre ciclos
REVALIDATE = 1800   # par presente o tempo todo e reanunciado para nova verificacao
ABSENT     = 600    # par fora das tabelas por mais tempo que isso e anunciado de novo
SCAN       = True   # roda /tool ip-scan na LAN antes de ler o ARP
SCAN_S     = 90     # duracao do ip-scan; a /24 inteira leva cerca de 80 s no RouterOS 6.40
ARP_SOURCE = "ssh"  # "ssh" ou "snmp" (os leases sempre vem por SSH)
COMMUNITY  = "mecanismo"                      # so para ARP_SOURCE = "snmp"

MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
CMD_ARP = (':foreach i in=[/ip arp find] do={:local a [/ip arp get $i]; '
           ':put (($a->"address")."|".($a->"mac-address"))}')
CMD_LEASE = (':foreach i in=[/ip dhcp-server lease find] do={'
             ':local l [/ip dhcp-server lease get $i]; '
             ':put (($l->"address")."|".($l->"mac-address")."|".($l->"status")'
             '."|".($l->"host-name")."|".($l->"class-id"))}')
CMD_SCAN = "/tool ip-scan address-range=%s-%s duration=%ds"


def utcnow():
    """Horario do servidor em UTC, no mesmo formato do ts do detector."""
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def baseline():
    with open(BASE) as f:
        return {k.lower().rstrip("*").rstrip(":"): v for k, v in json.load(f).items()}


def lookup(base, mac):
    """Entrada exata do MAC; sem ela, a entrada do prefixo (OUI) de 3 bytes."""
    if mac in base:
        return base[mac], "mac"
    if mac[:8] in base:
        return base[mac[:8]], "oui"
    return None, None


def in_lan(ip):
    try:
        return ipaddress.ip_address(ip) in LAN
    except ValueError:
        return False


def ssh(cmd, timeout=30):
    """Executa um comando no RouterOS e devolve as linhas nao vazias."""
    r = subprocess.run(["ssh", "-i", KEY, "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                        "%s@%s" % (USER, ROUTER), cmd],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0 or re.search(r"syntax error|bad command|not enough permissions",
                                      r.stdout):
        msg = (r.stderr or r.stdout).strip()[:200]
        raise RuntimeError(msg or "ssh retornou %d" % r.returncode)
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def arp_ssh():
    """Pares (mac, ip) da tabela ARP, so da LAN da filial e com MAC resolvido."""
    pairs = set()
    for line in ssh(CMD_ARP):
        ip, _, mac = line.partition("|")
        mac = mac.lower()
        if MAC.match(mac) and in_lan(ip):
            pairs.add((mac, ip))
    return pairs


def arp_snmp():
    """Mesma tabela pelo SNMP (IP-MIB ipNetToMediaPhysAddress)."""
    r = subprocess.run(["snmpwalk", "-v2c", "-c", COMMUNITY, "-Onqx", ROUTER,
                        "1.3.6.1.2.1.4.22.1.2"], capture_output=True, text=True, timeout=30)
    pairs = set()
    for line in r.stdout.splitlines():
        oid, _, val = line.strip().partition(" ")
        ip = ".".join(oid.split(".")[-4:])
        octets = [o.zfill(2) for o in re.split(r"[\s:]+", val.strip().strip('"'))
                  if re.fullmatch(r"[0-9A-Fa-f]{1,2}", o)]
        mac = ":".join(octets[:6]).lower()
        if MAC.match(mac) and in_lan(ip):
            pairs.add((mac, ip))
    return pairs


def leases():
    """Leases com status bound: {(mac, ip): {'hostname': ..., 'class_id': ...}}."""
    out = {}
    for line in ssh(CMD_LEASE):
        ip, mac, status, host, cls = (line.split("|") + [""] * 5)[:5]
        mac = mac.lower()
        if status == "bound" and MAC.match(mac) and in_lan(ip):
            out[(mac, ip)] = {"hostname": host.strip('"') or None,
                              "class_id": cls.strip('"') or None}
    return out


class Known:
    """Pares (MAC, IP) ja anunciados no events.jsonl, pelo detector ou pelo poller."""

    def __init__(self):
        self.seen, self.ip_mac, self.offset = {}, {}, 0
        self.announced = {}  # ultimo evento de cada par, de qualquer modulo

    def sync(self):
        """Le as linhas novas do events.jsonl desde a ultima leitura."""
        if not os.path.exists(OUT):
            return
        with open(OUT) as f:
            f.seek(self.offset)
            while True:
                line = f.readline()
                if not line.endswith("\n"):
                    break  # fim do arquivo ou linha ainda sendo gravada
                self.offset = f.tell()
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                mac, ip = (ev.get("mac") or "").lower(), ev.get("ip")
                if mac and ip:
                    self.seen[(mac, ip)] = self.announced[(mac, ip)] = time.time()
                    self.ip_mac[ip] = mac


def emit(mac, ip, source, lease, prev_mac, base, reason="novo"):
    entry, match = lookup(base, mac)
    ev = {
        "ts": utcnow(), "mac": mac, "ip": ip,
        "status": "authorized" if entry else "unknown",
        "match": match,
        "name": entry.get("name") if entry else None,
        "expected_os": entry.get("os") if entry else None,
        "hostname": lease.get("hostname") if lease else None,
        "class_id": lease.get("class_id") if lease else None,
        "source": source,
        "static": lease is None,
        "ip_prev_mac": prev_mac, "reason": reason,
    }
    with open(OUT, "a") as o:
        o.write(json.dumps(ev) + "\n")
    print(json.dumps(ev), flush=True)


def cycle(known, show):
    if SCAN:
        try:
            ssh(CMD_SCAN % (LAN[1], LAN[-2], SCAN_S), timeout=SCAN_S + 30)
        except Exception as e:
            print(json.dumps({"ts": utcnow(), "aviso": "ip-scan: %s" % e}), flush=True)
    arp = arp_snmp() if ARP_SOURCE == "snmp" else arp_ssh()
    bound = leases()
    known.sync()
    if show:
        for mac, ip in sorted(arp, key=lambda p: ipaddress.ip_address(p[1])):
            print("ARP   %-15s %s" % (ip, mac), flush=True)
        for (mac, ip), l in sorted(bound.items(), key=lambda i: ipaddress.ip_address(i[0][1])):
            print("LEASE %-15s %s %s %s" % (ip, mac, l["hostname"], l["class_id"]), flush=True)

    base, now = baseline(), time.time()
    for mac, ip in sorted(arp | set(bound), key=lambda p: ipaddress.ip_address(p[1])):
        last = known.seen.get((mac, ip))
        prev = known.ip_mac.get(ip)
        known.seen[(mac, ip)] = now
        known.ip_mac[ip] = mac
        if (last is not None and now - last <= ABSENT
                and now - known.announced.get((mac, ip), 0) <= REVALIDATE):
            continue
        in_arp, lease = (mac, ip) in arp, bound.get((mac, ip))
        source = "arp+dhcp-lease" if in_arp and lease else ("arp" if in_arp else "dhcp-lease")
        reason = ("novo" if last is None else
                  "reaparecimento" if now - last > ABSENT else "reverificacao")
        emit(mac, ip, source, lease, prev if prev and prev != mac else None, base, reason)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="faz um ciclo e sai")
    ap.add_argument("--show", action="store_true", help="mostra as tabelas lidas do roteador")
    a = ap.parse_args()
    known = Known()
    while True:
        try:
            cycle(known, a.show)
        except Exception as e:
            print(json.dumps({"ts": utcnow(), "erro": "%s: %s" % (type(e).__name__, e)}),
                  flush=True)
        if a.once:
            break
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
