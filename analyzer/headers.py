import re
from email import message_from_string
from email.utils import getaddresses

from .domini import dominio_registrabile, stessa_organizzazione


def parse_headers(raw_headers: str) -> dict:
    """
    Riceve una stringa con tutti gli headers grezzi
    e restituisce un dizionario {nome_header: valore}.

    Se un header compare più volte (Received, Authentication-Results, ...)
    si tiene il PRIMO, cioè quello aggiunto dal server più vicino a te:
    quelli più in basso possono essere stati scritti dal mittente.
    """
    raw = (raw_headers or "").replace("\r\n", "\n").lstrip("﻿").lstrip("\n")
    msg = message_from_string(raw)
    headers: dict = {}
    for k, v in msg.items():
        if k not in headers:
            headers[k] = " ".join(_decodifica(v).split())
    return headers


def _decodifica(valore) -> str:
    """Decodifica gli header RFC 2047 (=?UTF-8?B?...?=) in testo leggibile."""
    from email.header import decode_header, make_header
    try:
        return str(make_header(decode_header(str(valore))))
    except Exception:
        return str(valore)


def _addr(value: str) -> str:
    coppie = getaddresses([value or ""])
    return coppie[0][1].lower() if coppie and coppie[0][1] else ""


def _dom(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].strip(".>").lower() if "@" in addr else ""


def _root(dom: str) -> str:
    """Dominio registrabile (eTLD+1): mail.x.ch -> x.ch, posta.x.co.uk -> x.co.uk."""
    return dominio_registrabile(dom)


def _esito(auth: str, mecc: str) -> str:
    m = re.search(rf"\b{mecc}=(\w+)", auth, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def detect_suspicious_headers(headers: dict) -> list:
    """
    Riceve il dizionario degli header e restituisce
    una lista di avvisi di rischio.
    """
    warnings = []

    from_ = headers.get("From", "")
    spf_hdr = headers.get("Received-SPF", "")
    auth = headers.get("Authentication-Results", "") or headers.get("ARC-Authentication-Results", "")

    from_addr = _addr(from_)
    from_dom = _dom(from_addr)

    # FROM strano
    if "@" not in from_:
        warnings.append("⚠️ FROM sospetto: formato anomalo")

    # SPF: prima Authentication-Results, poi Received-SPF
    spf = _esito(auth, "spf") or (spf_hdr.split()[0].lower() if spf_hdr.strip() else "")
    dkim = _esito(auth, "dkim")
    dmarc = _esito(auth, "dmarc")

    if spf in ("fail", "permerror"):
        warnings.append("❌ SPF FAIL (possibile spoofing)")
    elif spf == "softfail":
        warnings.append("⚠️ SPF SOFTFAIL (mittente non autorizzato in modo esplicito)")
    if dmarc == "fail":
        warnings.append("❌ DMARC FAIL (policy non rispettata)")
    if dkim == "fail":
        warnings.append("❌ DKIM FAIL (firma non valida)")

    # Se non c'è nulla di autenticazione
    if not spf and not dkim and not dmarc:
        warnings.append("ℹ️ Nessuna info SPF/DKIM/DMARC trovata")

    # Allineamento: dominio che ha superato SPF/DKIM diverso dal From
    m = re.search(r"smtp\.mailfrom=([^\s;]+)", auth, re.IGNORECASE)
    mailfrom_dom = _dom(m.group(1)) if m and "@" in m.group(1) else (m.group(1).lower() if m else "")
    if spf == "pass" and from_dom and mailfrom_dom and not stessa_organizzazione(mailfrom_dom, from_dom):
        warnings.append(f"ℹ️ SPF pass ma per un altro dominio ({mailfrom_dom}) – non allineato al From ({from_dom})")

    # Reply-To verso un altro dominio: le risposte vanno altrove (tipico di BEC/phishing)
    reply_dom = _dom(_addr(headers.get("Reply-To", "")))
    if reply_dom and from_dom and not stessa_organizzazione(reply_dom, from_dom):
        warnings.append(f"⚠️ REPLY-TO MISMATCH: le risposte vanno a {reply_dom}, il From è {from_dom}")

    # Return-Path diverso: comune nelle newsletter, quindi solo informativo
    rp_dom = _dom(_addr(headers.get("Return-Path", "")))
    if rp_dom and from_dom and not stessa_organizzazione(rp_dom, from_dom):
        warnings.append(f"ℹ️ Return-Path su altro dominio ({rp_dom}) – normale per newsletter/servizi di invio")

    return warnings


def risk_score(issues: list) -> int:
    score = 0

    for issue in issues:
        if "SPF FAIL" in issue:
            score += 30
        if "SPF SOFTFAIL" in issue:
            score += 15
        if "DKIM FAIL" in issue:
            score += 30
        if "DMARC FAIL" in issue:
            score += 30
        if "FROM sospetto" in issue:
            score += 10
        if "REPLY-TO MISMATCH" in issue:
            score += 20
        if "non allineato" in issue:
            score += 5

    # Limita massimo a 100
    return min(score, 100)
