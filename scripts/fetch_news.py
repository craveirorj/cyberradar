#!/usr/bin/env python3
"""CyberRadar - recolhe notícias de ciber via RSS, traduz para PT-PT e grava data/news.json.

Corre de 20 em 20 minutos no GitHub Actions (gratuito). Uma fonte que falhe é ignorada.
"""
import hashlib
import html
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
from deep_translator import GoogleTranslator

ROOT = Path(__file__).resolve().parent.parent
FEEDS = ROOT / "feeds.json"
OUT = ROOT / "data" / "news.json"
MAX_AGE_DAYS = 14
MAX_ITEMS = 600
MAX_NEW_TRANSLATIONS = 150  # por execução, para não abusar do serviço gratuito

CATEGORIES = [
    ("Ransomware", r"ransomware|lockbit|akira|resgate"),
    ("Vulnerabilidade", r"cve-\d|vulnerab|zero-day|0-day|patch|exploit|rce\b"),
    ("Malware", r"malware|trojan|botnet|infostealer|backdoor|spyware|stealer"),
    ("Phishing/Fraude", r"phishing|scam|fraud|burla|golpe|smishing|vishing"),
    ("Fuga de dados", r"data breach|leak|fuga de dados|vazamento|breach|exposed"),
    ("Ataque/APT", r"apt\d*|nation-state|espionage|ddos|campaign|ataque|hackers?"),
    ("Regulação", r"nis2|gdpr|rgpd|regulat|compliance|cncs|enisa|lei\b"),
    ("IA", r"\bai\b|artificial intelligence|llm|inteligência artificial|deepfake"),
]


def clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def categorize(title: str, summary: str) -> str:
    blob = f"{title} {summary}".lower()
    for name, pattern in CATEGORIES:
        if re.search(pattern, blob):
            return name
    return "Geral"


def entry_time(entry) -> datetime:
    for key in ("published_parsed", "updated_parsed"):
        value = entry.get(key)
        if value:
            return datetime(*value[:6], tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def translate(text: str, translator: GoogleTranslator) -> str:
    if not text:
        return text
    try:
        return translator.translate(text[:1800]) or text
    except Exception as exc:  # serviço gratuito pode falhar; fica no original
        print(f"  tradução falhou: {exc}", file=sys.stderr)
        return text


def main() -> int:
    feeds = json.loads(FEEDS.read_text(encoding="utf-8"))["feeds"]
    old = {}
    if OUT.exists():
        try:
            old = {i["id"]: i for i in json.loads(OUT.read_text(encoding="utf-8"))["items"]}
        except Exception:
            old = {}

    translator = GoogleTranslator(source="auto", target="pt")
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    items = dict(old)
    status = []
    new_translations = 0

    for feed in feeds:
        name = feed["name"]
        try:
            parsed = feedparser.parse(feed["url"], agent="CyberRadar/1.0")
            entries = parsed.entries
            if not entries:
                raise RuntimeError("sem entradas (feed vazio ou bloqueado)")
        except Exception as exc:
            print(f"[FALHOU] {name}: {exc}", file=sys.stderr)
            status.append({"source": name, "ok": False, "error": str(exc)[:120]})
            continue

        added = 0
        for e in entries[:40]:
            link = e.get("link")
            title = clean(e.get("title", ""))
            if not link or not title:
                continue
            published = entry_time(e)
            if published < cutoff:
                continue
            summary = clean(e.get("summary", ""))[:600]
            kw = feed.get("keywords")
            if kw and not re.search("|".join(kw), f"{title} {summary}".lower()):
                continue

            uid = hashlib.sha1(link.encode()).hexdigest()[:16]
            if uid in items:
                continue

            # Limite de traduções atingido: não guardar já, fica para a próxima execução
            if feed["lang"] != "pt" and new_translations >= MAX_NEW_TRANSLATIONS:
                continue

            title_pt, summary_pt = title, summary
            translated = False
            if feed["lang"] != "pt":
                title_pt = translate(title, translator)
                summary_pt = translate(summary, translator) if summary else ""
                translated = True
                new_translations += 1
                time.sleep(0.3)

            items[uid] = {
                "id": uid,
                "source": name,
                "region": feed["region"],
                "lang": feed["lang"],
                "link": link,
                "published": published.isoformat(),
                "title": title_pt,
                "summary": summary_pt,
                "title_original": title if translated else None,
                "category": categorize(title, summary),
                "translated": translated,
            }
            added += 1
        print(f"[OK] {name}: +{added}")
        status.append({"source": name, "ok": True, "added": added})

    kept = [i for i in items.values() if datetime.fromisoformat(i["published"]) >= cutoff]
    kept.sort(key=lambda i: i["published"], reverse=True)
    kept = kept[:MAX_ITEMS]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "updated": datetime.now(timezone.utc).isoformat(),
                "sources": status,
                "items": kept,
            },
            ensure_ascii=False,
            indent=1,
        ),
        encoding="utf-8",
    )
    print(f"Total: {len(kept)} notícias, {sum(1 for s in status if s['ok'])}/{len(status)} fontes OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
