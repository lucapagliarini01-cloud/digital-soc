# analyzer/email_body.py
"""
Decodifica il CORPO dell'email (non solo gli header).

Le email reali hanno il corpo codificato (quoted-printable o base64) e spesso in HTML:
cercare parole o link nel testo grezzo non funziona. Qui:
  - si decodifica ogni parte text/plain e text/html
  - dall'HTML si estraggono testo visibile, link <a href> (con il testo mostrato) e form
  - si elencano gli allegati con SHA256
Nessun link viene aperto, nessun allegato viene eseguito.
"""
from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from email import policy
from email.parser import Parser
from html.parser import HTMLParser
from typing import Any, Dict, List, Tuple

URL_RE = re.compile(r"https?://[^\s<>\"'()\[\]]{1,2048}", re.IGNORECASE)

# Limiti contro email costruite per rallentare/bloccare l'analisi (HTML enormi, migliaia di link)
MAX_PARTE = 2_000_000       # caratteri analizzati per ogni parte testo/HTML
MAX_TESTO = 500_000         # caratteri di testo visibile usati per le parole chiave
MAX_URL = 500               # URL considerati per email
MAX_PARTI = 200             # parti MIME esaminate


class _HTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: List[str] = []
        self.links: List[Tuple[str, str]] = []   # (href, testo visibile)
        self.forms: List[str] = []
        self._href = None
        self._buf: List[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tag = tag.lower()
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "a":
            self._href = (a.get("href") or "").strip()
            self._buf = []
        elif tag == "form":
            self.forms.append((a.get("action") or "").strip())
        elif tag in ("br", "p", "div", "tr", "li", "h1", "h2", "h3"):
            self.text.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._buf).split())))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._buf.append(data)


def _pulisci_url(u: str) -> str:
    return u.rstrip(".,;:!?»”'\"").replace("&amp;", "&")


def extract_body(raw: str) -> Dict[str, Any]:
    """Come _estrai, ma con una piccola cache: pipeline, urls e phishing analizzano la stessa email
    (su un HTML enorme rifare il lavoro tre volte triplicava i tempi)."""
    r = _estrai_cache(raw or "")
    return {k: (list(v) if isinstance(v, list) else v) for k, v in r.items()}


@lru_cache(maxsize=4)
def _estrai_cache(raw: str) -> Dict[str, Any]:
    return _estrai(raw)


def _estrai(raw: str) -> Dict[str, Any]:
    """
    Ritorna:
      {
        "has_body": bool,          # False se sono stati incollati solo gli header
        "text": str,               # testo leggibile (plain + html ripulito)
        "urls": [str],             # URL unici, in ordine di comparsa
        "html_links": [(href, testo)],
        "forms": [action],
        "attachments": [{"name", "content_type", "size", "sha256"}],
      }
    """
    raw = (raw or "").replace("\r\n", "\n").lstrip("﻿")
    raw = raw.lstrip("\n")
    msg = Parser(policy=policy.default).parsestr(raw)

    texts: List[str] = []
    urls: List[str] = []
    links: List[Tuple[str, str]] = []
    forms: List[str] = []
    attachments: List[Dict[str, Any]] = []
    limiti: List[str] = []                       # limiti superati: l'analisi è parziale

    for n_parte, part in enumerate(msg.walk()):
        if n_parte > MAX_PARTI:
            limiti.append(f"oltre {MAX_PARTI} parti MIME")
            break
        if part.is_multipart():
            continue
        filename = part.get_filename()
        ctype = part.get_content_type()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        if filename or part.get_content_disposition() == "attachment":
            attachments.append({
                "name": filename or "(senza nome)",
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            })
            continue
        if ctype not in ("text/plain", "text/html"):
            continue

        try:
            content = payload[:MAX_PARTE * 4].decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            content = payload[:MAX_PARTE * 4].decode("utf-8", errors="replace")
        if len(content) > MAX_PARTE:
            limiti.append(f"parte {ctype} oltre {MAX_PARTE // 1_000_000} milioni di caratteri")
            content = content[:MAX_PARTE]

        if ctype == "text/html":
            ex = _HTMLExtractor()
            try:
                ex.feed(content)
            except Exception:
                pass
            links += ex.links
            forms += ex.forms
            urls += [h for h, _ in ex.links if h.lower().startswith(("http://", "https://"))]
            urls += [f for f in ex.forms if f.lower().startswith(("http://", "https://"))]
            visible = re.sub(r"[ \t]+", " ", "".join(ex.text))
            # URL scritti nel testo VISIBILE (non nel sorgente HTML: DOCTYPE, xmlns, CSS e
            # immagini contengono indirizzi tecnici come w3.org che non sono link per l'utente)
            urls += URL_RE.findall(visible)
            texts.append(re.sub(r"\n\s*\n+", "\n\n", visible))
        else:
            texts.append(content)
            urls += URL_RE.findall(content)

    seen, unique = set(), []
    for u in urls:
        u = _pulisci_url(u)
        if u and u not in seen:
            seen.add(u)
            unique.append(u)

    text = "\n".join(t.strip() for t in texts if t.strip())
    if len(text) > MAX_TESTO:
        limiti.append("testo oltre il limite analizzato")
        text = text[:MAX_TESTO]
    if len(unique) > MAX_URL:
        limiti.append(f"{len(unique)} link (analizzati i primi {MAX_URL})")
        unique = unique[:MAX_URL]
    return {
        "has_body": bool(text) or bool(attachments),
        "text": text,
        "urls": unique,
        "html_links": links,
        "forms": forms,
        "attachments": attachments,
        "limiti": list(dict.fromkeys(limiti)),
    }
