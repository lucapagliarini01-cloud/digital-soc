# analyzer/autenticazione.py
"""
Quanto ci si può fidare di SPF / DKIM / DMARC scritti nell'email?

L'header Authentication-Results è testo: chiunque può scriverne uno falso ("dmarc=pass") prima di
spedire. Vale solo se l'ha aggiunto un server di fiducia (il campo "authserv-id", es. mx.google.com),
cioè il provider che ha RICEVUTO l'email. Regola usata qui:

  - i risultati NEGATIVI (fail, softfail) si accettano sempre: un attaccante non ha motivo di inventarli;
  - i risultati POSITIVI (pass) contano solo se:
      a) l'Authentication-Results viene da un server di fiducia, oppure
      b) la firma DKIM è stata verificata DA NOI, crittograficamente, con la chiave pubblicata nel DNS
         del dominio firmatario (libreria dkimpy, facoltativa).

Se nessuna delle due, i "pass" vengono ignorati e nel report compare "autenticazione non verificabile".
"""
from __future__ import annotations

import re
from typing import Callable, Dict, Iterable, Optional, Tuple

# Server di ricezione dei provider più comuni (confronto per suffisso: x.mx.google.com -> mx.google.com)
SERVER_FIDATI = (
    "mx.google.com", "google.com",
    "icloud.com", "me.com",
    "yahoo.com", "aol.com",
    "outlook.com", "hotmail.com", "protection.outlook.com",
    "libero.it", "iol.it", "virgilio.it", "tim.it", "alice.it",
    "aruba.it", "arubapec.it", "register.it",
    "zoho.com", "zohomail.com", "zoho.eu",
    "fastmail.com", "messagingengine.com",
    "protonmail.ch", "proton.ch", "gmx.net", "web.de", "mail.ru",
)

_PASS = re.compile(r"\b(spf|dkim|dmarc|arc)=pass\b", re.I)


def authserv_id(ar: str) -> str:
    """Primo campo di Authentication-Results ("mx.google.com; spf=…"). Vuoto se manca (stile Microsoft)."""
    primo = (ar or "").split(";", 1)[0].strip()
    if not primo or "=" in primo:
        return ""
    return primo.split()[0].strip().lower().rstrip(".")


def server_fidato(server: str, extra: Iterable[str] = ()) -> bool:
    server = (server or "").lower()
    if not server:
        return False
    for f in tuple(SERVER_FIDATI) + tuple(x.strip().lower() for x in extra if x and x.strip()):
        if server == f or server.endswith("." + f):
            return True
    return False


def _dnsfunc_con_timeout(secondi: float = 4.0) -> Callable[[bytes], bytes]:
    def dnsfunc(nome: bytes, timeout: float = secondi) -> bytes:
        import dns.resolver
        try:
            r = dns.resolver.resolve(nome.decode().rstrip("."), "TXT", lifetime=secondi)
        except Exception:
            return b""
        for rr in r:
            return b"".join(rr.strings)
        return b""
    return dnsfunc


def verifica_dkim(raw: str, dnsfunc: Optional[Callable] = None) -> Tuple[bool, str]:
    """Verifica crittografica della PRIMA firma DKIM. Ritorna (valida, dominio d=). Mai eccezioni."""
    try:
        import dkim
    except ImportError:
        return False, ""
    try:
        dati = (raw or "").replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-8", errors="surrogateescape")
        if b"dkim-signature:" not in dati[:200_000].lower():
            return False, ""
        d = dkim.DKIM(dati)
        ok = d.verify(dnsfunc=dnsfunc or _dnsfunc_con_timeout())
        dominio = (d.domain or b"").decode(errors="replace").lower() if ok else ""
        return bool(ok), dominio
    except Exception:
        return False, ""


def valuta(headers: Dict[str, str], raw: str, fidati_extra: Iterable[str] = (),
           dkim_attivo: bool = False, dnsfunc: Optional[Callable] = None) -> Tuple[Dict[str, str], Dict]:
    """
    Ritorna (headers da usare nell'analisi, informazioni).
    Negli header restituiti, se l'Authentication-Results non è affidabile, i "pass" diventano "nonverificato"
    (così NESSUNA parte del motore li conta), e si aggiunge l'eventuale DKIM verificato da noi.
    """
    ar = headers.get("Authentication-Results", "") or ""
    server = authserv_id(ar)
    fidato = server_fidato(server, fidati_extra)
    info = {"server": server, "fidato": fidato, "dkim_verificato": False, "dkim_dominio": "",
            "pass_ignorati": False, "nota": ""}
    nuovi = dict(headers)
    # ARC-Authentication-Results non viene mai usato come fonte di fiducia
    nuovi.pop("ARC-Authentication-Results", None)
    if fidato:
        return nuovi, info

    if ar and _PASS.search(ar):
        info["pass_ignorati"] = True
        ar = _PASS.sub(lambda m: f"{m.group(1)}=nonverificato", ar)
    if dkim_attivo:
        ok, dominio = verifica_dkim(raw, dnsfunc)
        if ok and dominio:
            info["dkim_verificato"], info["dkim_dominio"] = True, dominio
            ar = (ar + "; " if ar else "") + f"dkim=pass (verificata da Digital SOC) header.d={dominio}"
    nuovi["Authentication-Results"] = ar
    if info["dkim_verificato"]:
        info["nota"] = (f"ℹ️ Firma DKIM verificata crittograficamente da Digital SOC (d={info['dkim_dominio']})"
                        + (f"; l'Authentication-Results di '{server}' non è tra i server fidati" if server else "") + ".")
    elif info["pass_ignorati"]:
        info["nota"] = (f"ℹ️ Autenticazione non verificabile: l'Authentication-Results è stato scritto da "
                        f"'{server or 'server senza nome'}', che non è tra i server fidati. I risultati 'pass' "
                        f"sono stati ignorati (potrebbero essere falsi).")
    return nuovi, info
