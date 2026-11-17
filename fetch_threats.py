#!/usr/bin/env python3
"""Recolhe dados de ameaças para o mapa "Ataques ao vivo" e grava data/threats.json.

Fontes (gratuitas):
- abuse.ch Feodo Tracker: servidores de comando e controlo de botnets (sem chave).
- Cloudflare Radar: principais origens e alvos de ataques DDoS (camadas 3/4) e a aplicações web (camada 7).
  Precisa do segredo CLOUDFLARE_API_TOKEN (token gratuito com permissão Radar: Read). Sem ele, esta parte é ignorada.
- abuse.ch URLhaus (sites que distribuem malware), abuse.ch ThreatFox (indicadores de malware),
  OpenPhish (phishing) e SANS DShield (IPs que fazem scans e força bruta): todas sem chave.
- País dos IPs: base DB-IP Lite (CC BY 4.0, https://db-ip.com), descarregada em cada execução.
Cada fonte falha sozinha, sem estragar as outras.
"""
import bisect
import csv
import gzip
import io
import ipaddress
import json
import os
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

OUT = Path(__file__).resolve().parent.parent / "data" / "threats.json"
UA = {"User-Agent": "Mozilla/5.0 (compatible; CyberRadar/1.0)"}


def feodo():
    r = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", headers=UA, timeout=30)
    r.raise_for_status()
    rows = r.json()
    if isinstance(rows, dict):
        rows = rows.get("data") or rows.get("blocklist") or []
    online = [x for x in rows if str(x.get("status", "")).lower() == "online"] or rows
    by_country = Counter((x.get("country") or "").upper() for x in online if x.get("country"))
    by_malware = Counter(x.get("malware") or "?" for x in online)
    recent = sorted(rows, key=lambda x: x.get("last_online") or x.get("first_seen") or "", reverse=True)[:25]
    return {
        "total": len(rows),
        "online": len(online),
        "by_country": dict(by_country.most_common(40)),
        "by_malware": dict(by_malware.most_common(8)),
        "recent": [
            {"country": (x.get("country") or "").upper(), "malware": x.get("malware") or "?",
             "port": x.get("port"), "seen": x.get("last_online") or x.get("first_seen")}
            for x in recent
        ],
    }


# ---------------------------------------------------------------- país por IP (DB-IP Lite)
class GeoIP:
    def __init__(self):
        self.starts, self.rows = [], []
        now = datetime.now(timezone.utc)
        months = [(now.year, now.month), (now.year - (now.month == 1), 12 if now.month == 1 else now.month - 1)]
        last = None
        for y, m in months:
            try:
                r = requests.get(f"https://download.db-ip.com/free/dbip-country-lite-{y}-{m:02d}.csv.gz", headers=UA, timeout=90)
                r.raise_for_status()
                data = gzip.decompress(r.content).decode("utf-8", "replace")
                break
            except Exception as exc:
                last = exc
        else:
            raise RuntimeError(f"DB-IP indisponível: {last}")
        tmp = []
        for a, b, cc in csv.reader(io.StringIO(data)):
            if ":" in a:
                continue
            tmp.append((int(ipaddress.IPv4Address(a)), int(ipaddress.IPv4Address(b)), cc))
        tmp.sort()
        self.starts = [t[0] for t in tmp]
        self.rows = tmp

    def cc(self, ip):
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return ""
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and self.rows[i][0] <= n <= self.rows[i][1]:
            c = self.rows[i][2]
            return "" if c in ("ZZ", "--") else c
        return ""


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return ""


def hosts_to_ips(urls, limit=250):
    hosts = []
    for u in urls:
        h = urlparse(u if "://" in u else "http://" + u).hostname
        if h and h not in hosts:
            hosts.append(h)
    hosts = hosts[:limit]
    ips = {}
    isip = re.compile(r"^\d+\.\d+\.\d+\.\d+$")
    todo = [h for h in hosts if not isip.match(h)]
    for h in hosts:
        if isip.match(h):
            ips[h] = h
    with ThreadPoolExecutor(24) as ex:
        for h, ip in zip(todo, ex.map(resolve, todo)):
            if ip:
                ips[h] = ip
    return [ips[h] for h in hosts if h in ips], hosts


def summarize(label, ips, geo, extra=None):
    c = Counter(geo.cc(ip) for ip in ips)
    c.pop("", None)
    return {"label": label, "total": len(ips), "by_country": dict(c.most_common(40)), **(extra or {})}


def urlhaus(geo):
    r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=UA, timeout=45)
    r.raise_for_status()
    urls, tags = [], Counter()
    for line in r.text.splitlines():
        if not line or line.startswith("#"):
            continue
        row = next(csv.reader([line]))
        if len(row) >= 7 and row[3].lower() == "online":
            urls.append(row[2])
            for t in (row[6] or "").split(","):
                if t.strip():
                    tags[t.strip()] += 1
    ips, hosts = hosts_to_ips(urls)
    return summarize("Sites que distribuem malware", ips, geo, {"total": len(urls), "tags": dict(tags.most_common(6))})


def openphish(geo):
    r = requests.get("https://openphish.com/feed.txt", headers=UA, timeout=45)
    r.raise_for_status()
    urls = [x.strip() for x in r.text.splitlines() if x.strip()]
    ips, hosts = hosts_to_ips(urls)
    return summarize("Sites de phishing", ips, geo, {"total": len(urls)})


def threatfox(geo):
    r = requests.get("https://threatfox.abuse.ch/export/json/recent/", headers=UA, timeout=60)
    r.raise_for_status()
    j = r.json()
    items = []
    for v in (j.values() if isinstance(j, dict) else j):
        items.extend(v if isinstance(v, list) else [v])
    ips, mal = [], Counter()
    for x in items:
        if not isinstance(x, dict):
            continue
        val = str(x.get("ioc_value", ""))
        if "ip" in str(x.get("ioc_type", "")):
            ips.append(val.split(":")[0])
            mal[x.get("malware_printable") or "?"] += 1
    return summarize("Indicadores de malware (IPs)", ips, geo, {"malware": dict(mal.most_common(6))})


def dshield(geo):
    r = requests.get("https://isc.sans.edu/api/sources/attacks/200?json", headers=UA, timeout=45)
    r.raise_for_status()
    rows = r.json()
    ips = []
    for x in rows:
        ip = str(x.get("ip", "")).strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            ips.append(".".join(str(int(p)) for p in ip.split(".")))
    return summarize("Scans e força bruta", ips, geo, {"reports": sum(int(x.get("reports") or x.get("count") or 0) for x in rows)})


def radar(path, key, token):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/radar/{path}",
        params={"dateRange": "1d", "limit": 15},
        headers={"Authorization": f"Bearer {token}", **UA},
        timeout=30,
    )
    r.raise_for_status()
    j = r.json()
    if not j.get("success", True):
        raise RuntimeError(str(j.get("errors"))[:200])
    top = (j.get("result") or {}).get("top_0") or []
    out = []
    for x in top:
        cc = x.get(key)
        if cc:
            out.append({"cc": cc.upper(), "name": x.get(key.replace("Alpha2", "Name")) or cc, "pct": float(x.get("value") or 0)})
    return out


def main():
    data = {"updated": datetime.now(timezone.utc).isoformat(), "errors": []}
    try:
        data["feodo"] = feodo()
        print(f"[Feodo] {data['feodo']['online']} servidores C2 ativos")
    except Exception as exc:
        data["errors"].append(f"Feodo: {str(exc)[:160]}")
        print(f"[Feodo] falhou: {exc}")

    try:
        geo = GeoIP()
        types = {}
        for key, fn in [("malware_urls", urlhaus), ("phishing", openphish), ("ioc", threatfox), ("scans", dshield)]:
            try:
                types[key] = fn(geo)
                print(f"[{key}] {types[key]['total']} itens, {len(types[key]['by_country'])} países")
            except Exception as exc:
                data["errors"].append(f"{key}: {str(exc)[:160]}")
                print(f"[{key}] falhou: {exc}")
        if types:
            data["types"] = types
    except Exception as exc:
        data["errors"].append(f"GeoIP: {str(exc)[:160]}")
        print(f"[GeoIP] falhou: {exc}")

    token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if token:
        cf = {}
        for name, path, key in [
            ("l7_origin", "attacks/layer7/top/locations/origin", "originCountryAlpha2"),
            ("l7_target", "attacks/layer7/top/locations/target", "targetCountryAlpha2"),
            ("l3_origin", "attacks/layer3/top/locations/origin", "originCountryAlpha2"),
            ("l3_target", "attacks/layer3/top/locations/target", "targetCountryAlpha2"),
        ]:
            try:
                cf[name] = radar(path, key, token)
            except Exception as exc:
                data["errors"].append(f"Cloudflare {name}: {str(exc)[:160]}")
                print(f"[Radar] {name} falhou: {exc}")
        if cf:
            data["cloudflare"] = cf
            print(f"[Radar] {len(cf)} listas obtidas")
    else:
        data["errors"].append("Cloudflare: falta o segredo CLOUDFLARE_API_TOKEN")

    # se tudo falhar, mantém o ficheiro anterior
    if "feodo" not in data and "cloudflare" not in data and "types" not in data and OUT.exists():
        print("Nada novo; ficheiro anterior mantido")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
