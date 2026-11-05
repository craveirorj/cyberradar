#!/usr/bin/env python3
"""CyberRadar - recolhe notícias de ciber via RSS, traduz e resume em PT-PT e grava data/news.json.

Corre de 20 em 20 minutos no GitHub Actions (gratuito). Uma fonte que falhe é ignorada.

Para cada notícia o Gemini (grátis, segredo GEMINI_API_KEY) escreve, com palavras próprias:
  - título em PT-PT, resumo de 2-4 frases, "porque importa" e "o que fazer".
Não se republica o artigo: guarda-se só este resumo e o link para a fonte.
Sem chave: usa o Google Translate "não oficial" (costuma ser bloqueado no GitHub) e fica só o excerto do RSS.
Se nada funcionar, a notícia fica em inglês (etiqueta EN) e é tratada numa execução futura.
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
MAX_AI_PER_RUN = 120          # notícias por execução
GEMINI_BATCH = 12             # notícias por pedido
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

# Rodapés automáticos dos feeds ("The post X appeared first on Y.", "Leia mais...")
BOILER = [
    re.compile(r"\s*(The post|The article|O post|A publicação|O artigo) .{0,400}?"
               r"(appeared first on|apareceu primeiro (em|no|na)|apareceu pela primeira vez (em|no|na)) .{0,120}$", re.I),
    re.compile(r"\s*(Read more|Continue reading|Leia mais|Ler mais|Saiba mais)\b.{0,80}$", re.I),
]


class QuotaError(Exception):
    pass


def clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def strip_boiler(text: str) -> str:
    text = text or ""
    for pattern in BOILER:
        text = pattern.sub("", text)
    return text.strip()


IMG_RE = re.compile(r"""<img[^>]+src=["']([^"']+)["']""", re.I)
BAD_IMG = re.compile(r"feedburner|pixel|spacer|1x1|smilies|emoji|gravatar|/avatar|\.svg($|\?)|doubleclick|adserver", re.I)


def good_image(url):
    if not url:
        return None
    url = url.strip()
    if url.startswith("//"):
        url = "https:" + url
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    if not url.startswith("https://") or BAD_IMG.search(url) or len(url) > 500:
        return None
    return url


def entry_image(e):
    """Endereço da imagem que o próprio feed indica (não se descarrega nem se guarda a imagem)."""
    for key in ("media_content", "media_thumbnail"):
        for m in e.get(key) or []:
            kind = (m.get("type") or m.get("medium") or "")
            if key == "media_thumbnail" or not kind or "image" in kind:
                u = good_image(m.get("url"))
                if u:
                    return u
    for en in (e.get("enclosures") or []) + [l for l in (e.get("links") or []) if l.get("rel") == "enclosure"]:
        if "image" in (en.get("type") or ""):
            u = good_image(en.get("href") or en.get("url"))
            if u:
                return u
    blobs = [c.get("value", "") for c in (e.get("content") or [])] + [e.get("summary", "")]
    for blob in blobs:
        for m in IMG_RE.finditer(blob or ""):
            u = good_image(m.group(1))
            if u:
                return u
    return None


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


# ---------------------------------------------------------------- IA (Gemini)
def gemini_batch(batch, key, state):
    payload = [
        {"i": n, "idioma": it["lang"], "t": it["title"], "x": (it.get("raw") or it["summary"])[:2500]}
        for n, it in enumerate(batch)
    ]
    prompt = (
        "És editor de uma app de notícias de cibersegurança para o público português, incluindo pequenas empresas. "
        "Para cada notícia abaixo escreve, em português europeu (PT-PT):\n"
        '- "t": o título (traduzido se estiver noutra língua; se já estiver em português, mantém-no igual);\n'
        '- "s": um resumo próprio de 3 a 5 frases, com palavras tuas (não copies frases do texto), '
        "com o essencial: o que aconteceu, quem e qual o impacto;\n"
        '- "k": 3 a 4 pontos-chave curtos (cada um com menos de 20 palavras), como lista de textos, '
        "também com palavras tuas (quem, o quê, como, impacto);\n"
        '- "w": porque importa, numa frase;\n'
        '- "a": o que fazer, 1 a 2 recomendações práticas e gerais de boas práticas ligadas ao tema '
        '(pode ser "" se não fizer sentido).\n'
        "Regras: usa só a informação do texto; não inventes nomes, números, datas nem atribuições; "
        "se o texto for curto, escreve um resumo curto; mantém nomes próprios, nomes de malware e de grupos, "
        "CVEs e siglas. Responde só com um array JSON, um objeto por notícia, no formato "
        '{"i": <número>, "t": ..., "s": ..., "k": [...], "w": ..., "a": ...}.\n\n'
        + json.dumps(payload, ensure_ascii=False)
    )
    body = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 8192, "responseMimeType": "application/json"},
    }
    last = ""
    while state["idx"] < len(GEMINI_MODELS):
        model = GEMINI_MODELS[state["idx"]]
        r = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": key, "Content-Type": "application/json"},
            json=body,
            timeout=120,
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
                t = str(o.get("t") or "").strip()
                s = str(o.get("s") or "").strip()
            except (KeyError, TypeError, ValueError, AttributeError):
                continue
            if 0 <= n < len(batch) and s:
                k = o.get("k") if isinstance(o.get("k"), list) else []
                k = [str(x).strip()[:220] for x in k if str(x).strip()][:4]
                out[n] = (t, s, str(o.get("w") or "").strip(), str(o.get("a") or "").strip(), k)
        return out
    raise RuntimeError(f"nenhum modelo Gemini respondeu ({last})")


def apply_brief(item, title, summary, why, todo, points=()):
    if item["lang"] != "pt" and not item["translated"]:
        item["title_original"] = item["title"]
        if title:
            item["title"] = title
        item["translated"] = True
    item["summary"] = summary
    item["why"] = why
    item["todo"] = todo
    item["points"] = list(points)
    item["enriched"] = True
    item.pop("raw", None)


def enrich_gemini(pending, key):
    done = 0
    state = {"idx": 0}
    for start in range(0, len(pending), GEMINI_BATCH):
        batch = pending[start:start + GEMINI_BATCH]
        try:
            result = gemini_batch(batch, key, state)
        except QuotaError as exc:
            print(f"[IA] {exc}; o resto fica para a próxima execução")
            break
        except Exception as exc:
            print(f"[IA] Gemini falhou: {exc}")
            break
        for n, (t, s, w, a, k) in result.items():
            apply_brief(batch[n], t, s, w, a, k)
            done += 1
        time.sleep(GEMINI_PAUSE)
    return done


# ---------------------------------------------------------------- reserva sem chave
def translate_google(pending):
    try:
        from deep_translator import GoogleTranslator
    except Exception as exc:
        print(f"[IA] deep-translator indisponível: {exc}")
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
                print(f"[IA] Google Translate bloqueado ({str(exc)[:80]}...). "
                      "Configura GEMINI_API_KEY para traduzir e resumir de forma fiável.")
                break
            continue
        if t:
            it["title_original"] = it["title"]
            it["title"] = t
            if s:
                it["summary"] = s
            it["translated"] = True
            done += 1
        time.sleep(0.6)
    return done


def main() -> int:
    feeds = json.loads(FEEDS.read_text(encoding="utf-8"))["feeds"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)
    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip())

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
                if not i.get("enriched"):
                    i["summary"] = strip_boiler(i.get("summary", ""))
                i.setdefault("enriched", False)
                items[i["id"]] = i
        except Exception as exc:
            print(f"[AVISO] não consegui ler o news.json anterior: {exc}")

    # a região e a língua seguem sempre o feeds.json (permite reclassificar notícias já guardadas)
    by_name = {f["name"]: f for f in feeds}
    for i in items.values():
        f = by_name.get(i["source"])
        if f:
            i["region"], i["lang"] = f["region"], f["lang"]

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
            excerpt = strip_boiler(clean(e.get("summary", "")))
            content = strip_boiler(clean(" ".join(c.get("value", "") for c in (e.get("content") or []))))
            body = content if len(content) > len(excerpt) else excerpt
            if kw and not re.search("|".join(kw), f"{title} {body[:800]}".lower()):
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
                "summary": excerpt[:600],
                "image": entry_image(e),
                "points": [],
                "title_original": None,
                "category": categorize(title, body[:600]),
                "translated": False,
                "enriched": False,
            }
            if has_key:  # o texto serve só de entrada para a IA e é apagado depois de resumido
                items[uid]["raw"] = body[:2500]
            added += 1
        print(f"[OK] {name}: +{added}")
        status.append({"source": name, "ok": True, "added": added})

    # ---- IA: traduzir + resumir as notícias ainda por tratar (as mais recentes primeiro)
    by_date = lambda seq: sorted(seq, key=lambda i: i["published"], reverse=True)
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    provider, done = "nenhum", 0
    if key:
        todo = by_date(i for i in items.values() if not i["enriched"])[:MAX_AI_PER_RUN]
        if todo:
            provider, done = "gemini", enrich_gemini(todo, key)
    else:
        todo = by_date(i for i in items.values() if i["lang"] != "pt" and not i["translated"])[:MAX_AI_PER_RUN]
        if todo:
            provider, done = "google", translate_google(todo)
    pending = sum(1 for i in items.values() if i["lang"] != "pt" and not i["translated"])
    unenriched = sum(1 for i in items.values() if not i["enriched"])
    print(f"[IA] {provider}: {done} tratadas agora | {pending} por traduzir | {unenriched} sem resumo")

    kept = [i for i in items.values() if datetime.fromisoformat(i["published"]) >= cutoff]
    kept.sort(key=lambda i: i["published"], reverse=True)
    kept = kept[:MAX_ITEMS]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                "updated": datetime.now(timezone.utc).isoformat(),
                "sources": status,
                "translation": {"provider": provider, "done": done, "pending": pending, "unenriched": unenriched},
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
