#!/usr/bin/env python3
"""detector.py v2 (Modo 1): deteccao de presenca pelos registros DHCP do CHR-FILIAL.

Cada pacote DHCP chega pelo Syslog como um cabecalho
('<servidor> received|sending <tipo> with id <n> ...') seguido de linhas 'campo = valor'.
O detector:
  - considera apenas pacotes do servidor da LAN da filial (SERVER) e IPs da LAN;
  - guarda Host-Name, Class-Id e Parameter-List da ultima mensagem de cada cliente
    (discover, request ou inform), sobrescrevendo inclusive com vazio;
  - a cada ACK do servidor grava um evento de presenca em events.jsonl, com status
    authorized ou unknown conforme o baseline (MAC completo ou prefixo OUI).
"""
import argparse, datetime, ipaddress, json, os, re, time

LOG    = "/var/log/filial/mikrotik.log"
BASE   = "/opt/mecanismo/baseline.json"
OUT    = "/var/log/mecanismo/events.jsonl"
SERVER = "dhcp-filial"                     # servidor DHCP da LAN no RouterOS
LAN    = ipaddress.ip_network("10.1.0.0/24")
DEDUP  = 60                                # segundos sem repetir o mesmo par (MAC, IP)

HEAD  = re.compile(r'^(\S+)\s+\S+\s+(.+?) (received|sending) (\w+) with id \d+')
FIELD = re.compile(r'^(\S+)\s+\S+\s+([\w()-]+)\s*=\s*(.*?)\s*$')
CLIENT_MSGS = ("discover", "request", "inform")


def utcnow():
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def epoch(ts):
    try:
        return datetime.datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return time.time()


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


class Detector:
    def __init__(self, out):
        self.out, self.pkt = out, None
        self.meta, self.last_msg, self.seen, self.ip_mac = {}, {}, {}, {}
        self.leased = set()  # pares (MAC, IP) que receberam concessao

    def close_packet(self):
        """Fecha o pacote corrente; se for mensagem do cliente, atualiza os metadados."""
        p, self.pkt = self.pkt, None
        if (not p or p["server"] != SERVER or p["dir"] != "received"
                or p["type"] not in CLIENT_MSGS):
            return
        mac = p["f"].get("chaddr")
        if mac:
            self.meta[mac] = {"hostname": p["f"].get("host-name"),
                              "class_id": p["f"].get("class-id"),
                              "param_list": p["f"].get("parameter-list")}
            self.last_msg[mac] = p["type"]

    def line(self, line):
        h = HEAD.match(line)
        if h:
            self.close_packet()
            ts, server, direction, mtype = h.groups()
            self.pkt = {"ts": ts, "server": server, "dir": direction,
                        "type": mtype.lower(), "f": {}}
            return
        m = FIELD.match(line)
        if not m or self.pkt is None:
            self.close_packet()
            return
        _, key, val = m.groups()
        key, val = key.lower(), val.strip('"')
        if key == "chaddr":
            val = val.lower()
        self.pkt["f"][key] = val
        if (key == "msg-type" and val.lower() == "ack"
                and self.pkt["dir"] == "sending" and self.pkt["server"] == SERVER):
            self.ack(self.pkt)

    def ack(self, p):
        f = p["f"]
        mac = f.get("chaddr")
        ip = f.get("yiaddr")
        if not ip or ip == "0.0.0.0":
            ip = f.get("ciaddr")
        if not mac or not ip or ip == "0.0.0.0" or not in_lan(ip):
            return
        if f.get("yiaddr") not in (None, "0.0.0.0"):
            self.leased.add((mac, ip))
        t = epoch(p["ts"])
        if t - self.seen.get((mac, ip), -1e12) <= DEDUP:
            return
        self.seen[(mac, ip)] = t
        prev = self.ip_mac.get(ip)
        self.ip_mac[ip] = mac
        meta, msg = self.meta.get(mac, {}), self.last_msg.get(mac)
        entry, match = lookup(baseline(), mac)
        ev = {"ts": p["ts"], "rx_ts": utcnow(), "mac": mac, "ip": ip,
              "status": "authorized" if entry else "unknown", "match": match,
              "name": entry.get("name") if entry else None,
              "expected_os": entry.get("os") if entry else None,
              "hostname": meta.get("hostname"), "class_id": meta.get("class_id"),
              "param_list": meta.get("param_list"),
              "source": "dhcp-inform" if msg == "inform" else "dhcp",
              "static": msg == "inform" and (mac, ip) not in self.leased,
              "ip_prev_mac": prev if prev and prev != mac else None}
        with open(self.out, "a") as o:
            o.write(json.dumps(ev) + "\n")
        print(json.dumps(ev), flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-start", action="store_true", help="le o log desde o inicio")
    ap.add_argument("--once", action="store_true", help="processa ate o fim do arquivo e sai")
    ap.add_argument("--log", default=LOG)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    d = Detector(a.out)
    f = open(a.log)
    if not a.from_start:
        f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if not line:
            if a.once:
                d.close_packet()
                break
            time.sleep(0.5)
            continue
        d.line(line.rstrip("\n"))


if __name__ == "__main__":
    main()
