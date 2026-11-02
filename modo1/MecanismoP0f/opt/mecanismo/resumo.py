#!/usr/bin/env python3
"""Resumo de evidencias: eventos e vereditos a partir de um horario UTC (opcional).
Uso: resumo.py [2026-11-01T20:45:00]"""
import json, sys, datetime

def t(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None

def rows(path):
    try:
        return [json.loads(l) for l in open(path) if l.strip()]
    except FileNotFoundError:
        return []

since = t(sys.argv[1] + "+00:00") if len(sys.argv) > 1 else None
print("== EVENTOS ==")
for e in rows("/var/log/mecanismo/events.jsonl"):
    if since and t(e["ts"]) < since:
        continue
    print(e["ts"][11:19], e["mac"], e["ip"], e.get("source", "dhcp"),
          "estatico" if e.get("static") else "-", e["status"], e.get("match"),
          e.get("class_id"), "prev=%s" % e.get("ip_prev_mac"), e.get("reason") or "")
print("== VEREDITOS ==")
for v in rows("/var/log/mecanismo/verdicts.jsonl"):
    if since and t(v["ts"]) < since:
        continue
    lat = int((t(v["ts"]) - t(v["event_ts"])).total_seconds()) if v.get("event_ts") else None
    print(v["ts"][11:19], "lat=%ss" % lat, v["ip"], v["mac"], v["verdict"],
          v["method"], v["observed_family"], "| p0f=%s" % v.get("p0f_os"),
          "ttl=%s dist=%s portas=%s" % (v["icmp_ttl"], v["dist"], v["open_ports"]),
          "|", ";".join(v["reasons"]) or "-")
