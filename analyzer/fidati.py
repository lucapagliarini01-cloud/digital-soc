# analyzer/fidati.py
"""
Mittenti fidati (allowlist) – ~/.config/digitalsoc/mittenti_fidati.json

Un mittente fidato passa come NON sospetto SOLO se l'email è autenticata
(DMARC pass allineato, oppure DKIM valido del dominio del mittente) e non ha
segnali "duri" (threat feed, link ingannevole, form, SPF/DKIM/DMARC fail, Reply-To altrove).
Se il mittente è fidato ma l'email NON è autenticata, è probabile una falsificazione:
il punteggio resta e si aggiunge un avviso.

Per i domini di posta gratuita (gmail.com, outlook.com, …) si possono rendere fidati
solo i singoli indirizzi, mai il dominio intero.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .domini import dominio_registrabile, stessa_organizzazione

CARTELLA = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "digitalsoc"
FILE = CARTELLA / "mittenti_fidati.json"
_lock = threading.Lock()

POSTA_GRATUITA = {
    "gmail.com", "googlemail.com", "outlook.com", "outlook.it", "hotmail.com", "hotmail.it", "live.com",
    "live.it", "msn.com", "yahoo.com", "yahoo.it", "libero.it", "virgilio.it", "tiscali.it", "alice.it",
    "tim.it", "icloud.com", "me.com", "mac.com", "privaterelay.appleid.com", "proton.me", "protonmail.com",
    "gmx.com", "gmx.it", "gmx.net", "aol.com", "mail.com", "yandex.com", "inwind.it", "email.it", "pec.it",
}


def _leggi() -> Dict:
    try:
        d = json.loads(FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        d = {}
    d.setdefault("domini", [])
    d.setdefault("indirizzi", [])
    return d


def _scrivi(d: Dict) -> None:
    CARTELLA.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(FILE)


def elenco() -> Dict[str, List[Dict]]:
    return _leggi()


def e_posta_gratuita(dominio: str) -> bool:
    d = (dominio or "").lower()
    return d in POSTA_GRATUITA or dominio_registrabile(d) in POSTA_GRATUITA


def aggiungi(valore: str, nota: str = "") -> str:
    """Aggiunge un dominio o un indirizzo. Ritorna 'dominio' | 'indirizzo'. Solleva ValueError se non valido."""
    v = (valore or "").strip().lower().strip("<>").lstrip("@")
    with _lock:
        d = _leggi()
        if "@" in v:
            if not re.match(r"^[^@\s]+@[^@\s]+\.[a-z0-9-]+$", v):
                raise ValueError("Indirizzo non valido")
            if v not in [x["valore"] for x in d["indirizzi"]]:
                d["indirizzi"].append({"valore": v, "nota": nota, "aggiunto": datetime.now().isoformat(timespec="seconds")})
            _scrivi(d)
            return "indirizzo"
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", v):
            raise ValueError("Dominio non valido")
        if e_posta_gratuita(v):
            raise ValueError(f"{v} è un servizio di posta usato da chiunque: rendi fidato il singolo indirizzo, "
                             "non il dominio intero.")
        if v not in [x["valore"] for x in d["domini"]]:
            d["domini"].append({"valore": v, "nota": nota, "aggiunto": datetime.now().isoformat(timespec="seconds")})
        _scrivi(d)
        return "dominio"


def rimuovi(valore: str) -> None:
    v = (valore or "").strip().lower()
    with _lock:
        d = _leggi()
        d["domini"] = [x for x in d["domini"] if x["valore"] != v]
        d["indirizzi"] = [x for x in d["indirizzi"] if x["valore"] != v]
        _scrivi(d)


def cerca(indirizzo: str, dominio: str) -> Optional[str]:
    """Ritorna la voce fidata che corrisponde al mittente (indirizzo esatto o dominio della stessa organizzazione)."""
    d = _leggi()
    ind = (indirizzo or "").lower()
    if ind and any(x["valore"] == ind for x in d["indirizzi"]):
        return ind
    dom = (dominio or "").lower()
    if not dom or e_posta_gratuita(dom):
        return None
    for x in d["domini"]:
        v = x["valore"]
        if dom == v or dom.endswith("." + v) or dominio_registrabile(dom) == dominio_registrabile(v) \
                or stessa_organizzazione(dom, v):
            return v
    return None


def autenticazione(auth_results: str, dominio_from: str) -> Dict[str, bool]:
    """Esito dell'autenticazione rispetto al dominio del From (dal primo Authentication-Results)."""
    a = (auth_results or "").lower()
    fail = any(f"{m}=fail" in a for m in ("spf", "dkim", "dmarc")) or "dmarc=permerror" in a
    m_hf = re.search(r"header\.from=([^\s;]+)", a)
    dmarc_ok = bool("dmarc=pass" in a and m_hf and dominio_from
                    and dominio_registrabile(m_hf.group(1)) == dominio_registrabile(dominio_from))
    m_dk = re.search(r"dkim=pass[^;]*?header\.(?:d|i)=@?([^\s;]+)", a)
    dkim_ok = bool(m_dk and dominio_from and stessa_organizzazione(m_dk.group(1), dominio_from))
    return {"autenticato": (dmarc_ok or dkim_ok) and not fail, "fail": fail, "dmarc": dmarc_ok, "dkim": dkim_ok}
