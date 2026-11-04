#!/usr/bin/env python3
"""CyberRadar - recolhe notícias de ciber via RSS, traduz para PT-PT e grava data/news.json.

Corre de 20 em 20 minutos no GitHub Actions (gratuito). Uma fonte que falhe é ignorada.

Tradução (por ordem):
  1. Gemini (grátis), se existir o segredo GEMINI_API_KEY no repositório. Traduz em lotes.
  2. Google Translate "não oficial", sem chave. Costuma ser bloqueado nos servidores do GitHub.
Se nenhuma funcionar, a notícia fica em inglês (etiqueta EN) e é traduzida numa execução futura.
"""
import hashlib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests

ROOT = Path(__file__).resolve().parent.parent
FEEDS = ROOT / "feeds.json"
OUT = ROOT / "data" / "news.json"
MAX_AGE_DAYS = 14
MAX_ITEMS = 600
MAX_TRANSLATE_PER_RUN = 120   # notícias por execução
GEMINI_BATCH = 20             # notícias por pedido
GEMINI_PAUSE = 7              # segundos entre pedidos (plano grátis: 10 por minuto)
GEMINI_MODELS = ["gemini-2.5-flash-lite", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite"]

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36 CyberRadar/1.0")

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


class QuotaError(Exception):
    pass


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


def fetch_feed(url: str):
    """Descarrega o feed com um User-Agent de browser (alguns sites bloqueiam o padrão)."""
    last = None
    for attempt in range(2):
        try:
            r = requests.get(
                url,
                headers={
                    "User-Agent": UA,
                    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
                },
                timeout=25,
            )
            r.raise_for_status()
            entries = feedparser.parse(r.content).entries
            if not entries:
                raise RuntimeError("resposta sem notícias (feed vazio ou página HTML)")
            return entries
        except Exception as exc:
            last = exc
            time.sleep(2)
    raise last


# ---------------------------------------------------------------- tradução
def gemini_batch(batch, key, state):
    payload = [{"i": n, "t": it["title"], "s": it["summary"][:350]} for n, it in enumerate(batch)]
    prompt = (
        "Traduz para português europeu (PT-PT) os títulos e resumos de notícias de cibersegurança abaixo. "
        "Mantém nomes próprios, nomes de malware e de grupos, CVEs, siglas e termos técnicos habituais "
        "(ransomware, phishing, zero-day) sem tradução forçada. Não acrescentes nada. "
        "Responde só com um array JSON com um objeto por notícia, no formato "
        '{"i": <número>, "t": <título traduzido>, "s": <resumo traduzido, ou "" se não houver>}.\n\n'
        + json.dumps(payload, ensure_ascii=False)
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
    }
    last = ""
    while state["idx"] < len(GEMINI_MODELS):
        model = GEMINI_MODELS[state["idx"]]
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=body,
            timeout=90,
        )
        if r.status_code == 429:
            raise QuotaError("limite do plano grátis atingido")
        if r.status_code in (400, 403, 404):
            last = f"{model}: HTTP {r.status_code} {r.text[:160]}"
            state["idx"] += 1
            continue
        r.raise_for_status()
        text = r.json()["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(text)
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [])
        out = {}
        for o in data:
            try:
                n = int(o["i"])
                t = str(o["t"]).strip()
            except (KeyError, TypeError, ValueError):
                continue
            if 0 <= n < len(batch) and t:
                out[n] = (t, str(o.get("s") or "").strip())
        return out
    raise RuntimeError(f"nenhum modelo Gemini respondeu ({last})")


def apply_translation(item, title, summary):
    item["title_original"] = item["title"]
    item["title"] = title
    if summary:
        item["summary"] = summary
    item["translated"] = True


def translate_gemini(pending, key):
    done = 0
    state = {"idx": 0}
    for start in range(0, len(pending), GEMINI_BATCH):
        batch = pending[start:start + GEMINI_BATCH]
        try:
            result = gemini_batch(batch, key, state)
        except QuotaError as exc:
            print(f"[TRADUÇÃO] {exc}; o resto fica para a próxima execução")
            break
        except Exception as exc:
            print(f"[TRADUÇÃO] Gemini falhou: {exc}")
            break
        for n, (t, s) in result.items():
            apply_translation(batch[n], t, s)
            done += 1
        time.sleep(GEMINI_PAUSE)
    return done


def translate_google(pending):
    try:
        from deep_translator import GoogleTranslator
    except Exception as exc:
        print(f"[TRADUÇÃO] deep-translator indisponível: {exc}")
        return 0
    tr = GoogleTranslator(source="auto", target="pt")
    done = fails = 0
    for it in pending:
        try:
            t = tr.translate(it["title"][:1800])
            s = tr.translate(it["summary"][:1800]) if it["summary"] else ""
        except Exception as exc:
            fails += 1
            if fails >= 3:
                print(f"[TRADUÇÃO] Google Translate bloqueado ({str(exc)[:80]}...). "
                      "Configura GEMINI_API_KEY para traduzir de forma fiável.")
                break
            continue
        if t:
            apply_translation(it, t, s)
            done += 1
        time.sleep(0.6)
    return done


def main() -> int:
    feeds = json.loads(FEEDS.read_text(encoding="utf-8"))["feeds"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)

    items = {}
    if OUT.exists():
        try:
            for i in json.loads(OUT.read_text(encoding="utf-8"))["items"]:
                if i.get("demo"):
                    continue
                # Repara traduções antigas que falharam e ficaram marcadas como feitas
                if i.get("translated") and i.get("title_original") == i.get("title"):
                    i["translated"] = False
                    i["title_original"] = None
                items[i["id"]] = i
        except Exception as exc:
            print(f"[AVISO] não consegui ler o news.json anterior: {exc}")

    status = []
    for feed in feeds:
        name = feed["name"]
        try:
            entries = fetch_feed(feed["url"])
        except Exception as exc:
            msg = str(exc)[:140]
            print(f"[FALHOU] {name}: {msg}")
            status.append({"source": name, "ok": False, "error": msg})
            continue

        added = 0
        kw = feed.get("keywords")
        for e in entries[:40]:
            link = e.get("link")
            title = clean(e.get("title", ""))
            if not link or not title:
                continue
            published = entry_time(e)
            if published < cutoff:
                continue
            summary = clean(e.get("summary", ""))[:600]
            if kw and not re.search("|".join(kw), f"{title} {summary}".lower()):
                continue
            uid = hashlib.sha1(link.encode()).hexdigest()[:16]
            if uid in items:
                continue
            items[uid] = {
                "id": uid,
                "source": name,
                "region": feed["region"],
                "lang": feed["lang"],
                "link": link,
                "published": published.isoformat(),
                "title": title,
                "summary": summary,
                "title_original": None,
                "category": categorize(title, summary),
                "translated": False,
            }
            added += 1
        print(f"[OK] {name}: +{added}")
        status.append({"source": name, "ok": True, "added": added})

    # ---- tradução das notícias estrangeiras que ainda estão por traduzir (as mais recentes primeiro)
    pending = sorted(
        (i for i in items.values() if i["lang"] != "pt" and not i["translated"]),
        key=lambda i: i["published"],
        reverse=True,
    )[:MAX_TRANSLATE_PER_RUN]
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    provider, done = "nenhum", 0
    if pending:
        if key:
            provider, done = "gemini", translate_gemini(pending, key)
        else:
            provider, done = "google", translate_google(pending)
    still_pending = sum(1 for i in items.values() if i["lang"] != "pt" and not i["translated"])
    print(f"[TRADUÇÃO] {provider}: {done} traduzidas agora, {still_pending} por traduzir")

    kept = [i for i in items.values() if datetime.fromisoformat(i["published"]) >= cutoff]
    kept.sort(key=lambda i: i["published"], reverse=True)
    kept = kept[:MAX_ITEMS]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "updated": datetime.now(timezone.utc).isoformat(),
                "sources": status,
                "translation": {"provider": provider, "done": done, "pending": still_pending},
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
