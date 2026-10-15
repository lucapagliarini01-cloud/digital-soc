#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phishing.py – Motore PHISHING "MAX SENSITIVITY" per Digital SOC

Versione più aggressiva:
- punteggi più alti per mismatch domini / credenziali / brand
- soglie per HIGH/CRITICAL abbassate
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from difflib import SequenceMatcher
import re

from .urls import extract_domain, analyze_domain
from .email_body import extract_body
from .domini import (dominio_registrabile, dominio_ufficiale_del_brand, etichetta, link_neutro,
                     link_tracciamento, stessa_organizzazione)

# ------------------------- REGOLE STATICHE ------------------------- #

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "club", "support", "work",
    "gq", "tk", "ml", "cf", "ga", "loan", "win", "men", "live"
}

URGENCY_KEYWORDS = [
    "urgente", "immediato", "subito", "entro 24 ore",
    "important notice", "urgent", "immediately", "asap",
    "azione richiesta", "azione necessaria"
]

CREDENTIAL_KEYWORDS = [
    "password", "credenziali", "verifica account", "verifica il tuo account",
    "account verification", "reset password", "reimposta la password",
    "cambia la password", "cambiare la password", "cambiare la tua password",
    "cambia password", "modifica la password", "aggiorna il tuo profilo",
    "conferma il tuo account", "collegati al tuo account", "conferma le tue credenziali",
    "verify your account", "change your password", "reset your password",
    "passwort", "mot de passe",
    # invito ad autenticarsi (tipico del credential phishing)
    "effettua l'accesso", "effettuare l'accesso", "accedi al tuo account", "accedi subito",
    "accedi per", "sign in to", "log in to your", "login to your",
]

# Falso incidente / minaccia sull'account (es. "cambia la password per un incidente di sicurezza")
INCIDENT_KEYWORDS = [
    "incidente di sicurezza", "violazione dei dati", "violazione di sicurezza", "data breach",
    "accesso non autorizzato", "accesso sospetto", "attività sospetta", "attivita sospetta",
    "attività insolita", "security incident", "security alert", "unusual activity",
    "unusual sign-in", "unauthorized access", "account sospeso", "account verrà sospeso",
    "account sarà sospeso", "account bloccato", "account suspended", "account locked",
]

# Regole a espressione regolare per BEC / social engineering: (nome, regex, peso)
BEC_RULES = [
    ("Scoraggia la verifica (non chiamare / sono in riunione)",
     r"non (contattarmi|chiamarmi|telefonarmi)|evitate? di (chiamare|contattare)|non chiamare|"
     r"sono in riunione|non posso rispondere al telefono|sono in viaggio|do not call|i'?m in a meeting", 20),
    ("Chiede di disattivare protezioni / abilitare macro",
     r"disattiv\w* (l'|il |i |le )?(antivirus|controll\w* di sicurezza|protezion\w*|firewall)|"
     r"abilita\w* (le )?macro|enable (editing|content|macros)|disable (your )?antivirus", 45),
    ("Gift card / buoni regalo", r"gift ?cards?|buon[oi] regalo|carte? regalo|google play card|itunes card", 25),
    ("Cambio coordinate bancarie",
     r"(nuovo|nuove|cambio( di)?|aggiornat[oe]) (iban|conto|coordinate)|new (bank account|iban)", 20),
    ("Richiesta di dati interni / elenchi",
     r"(lista|elenco) (degli |dei |del )?(account|utenti|dipendenti|amministrator\w*)|buste paga|dati della carta", 15),
    ("Segretezza", r"\briservat[oa]\b|\bconfidenzial[ei]\b|\bconfidential\b|non (dirlo|parlarne)", 10),
    ("Scadenza in minuti/ore", r"entro \d+ ?(minuti|ore)|per evitare che (venga|sia) (cancellat|eliminat|sospes)\w*", 10),
    ("Invito ad accedere / cliccare", r"effettua (l')?accesso|accedi (subito|ora|qui)|clicca (qui|sul link)|click here", 4),
    ("Allegato/documento protetto", r"(fattura|documento|file|allegato) (e |è )?(protett|cifrat)\w*|password[- ]protected", 10),
]

# Pagamenti / BEC
PAYMENT_KEYWORDS = [
    "iban", "bonifico", "coordinate bancarie", "nuovo conto", "gift card", "carte regalo",
    "buoni regalo", "wire transfer", "bank details",
]

BRAND_OFFICIAL_DOMAINS: Dict[str, List[str]] = {
    "amazon":   ["amazon"],
    "paypal":   ["paypal"],
    "apple":    ["apple"],
    "google":   ["google", "gmail"],
    "microsoft":["microsoft", "outlook", "live"],
    "unicredit":["unicredit"],
    "intesa":   ["intesasanpaolo", "intesa"],
    "poste":    ["poste", "postepay"],
    "dhl":      ["dhl"],
    "ups":      ["ups"],
    "gls":      ["gls"],
}

EMAIL_RE = re.compile(r"<([^>]+)>")
IP_URL_RE = re.compile(r"^https?://\d{1,3}(\.\d{1,3}){3}", re.IGNORECASE)


# ------------------------- FUNZIONI UTILI ------------------------- #

def _norm(s: str) -> str:
    return s.strip().lower()


def _similar(a: str, b: str) -> float:
    a = _norm(a)
    b = _norm(b)
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _get_email_from_header(value: str) -> str:
    if not value:
        return ""
    m = EMAIL_RE.search(value)
    return m.group(1) if m else value.strip()


def _get_domain_from_email(addr: str) -> str:
    if "@" not in addr:
        return ""
    return addr.split("@", 1)[1].strip().lower()


def _contains_any(text: str, words: List[str]) -> bool:
    return any(w in text for w in words)


def _classify_level(score: int) -> str:
    # MAX SENSITIVITY: soglie più basse
    if score >= 70:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


# Frasi di sicurezza tipiche dei mittenti legittimi ("non ti chiederemo MAI la password"):
# parlano di password ma per mettere in guardia, quindi vanno tolte prima di cercare le parole chiave.
_AVVISO_SICUREZZA = re.compile(
    r"\bmai\b[^.!?\n]{0,80}\b(password|credenzial\w*|pin|codic\w*|dati personali|otp)\b"
    r"|\b(password|credenzial\w*|pin|codic\w*)\b[^.!?\n]{0,80}\bmai\b"
    r"|\bnever ask\w*|will never (ask|request)|diffida\w* (da|di) (email|messaggi|sms)|tentativi di (phishing|frode)"
    r"|non (rispondere|cliccare) (a|su) (email|messaggi|sms) sospett\w*", re.I)
_FINE_FRASE = re.compile(r"([.!?\n])")


def _togli_avvisi_sicurezza(testo: str) -> str:
    """Toglie le FRASI che contengono un avviso di sicurezza. Lavora frase per frase (tempo lineare):
    la versione con [^.!?]* davanti diventava lentissima su testi lunghi senza punteggiatura (ReDoS)."""
    pezzi = _FINE_FRASE.split(testo)
    out = []
    i = 0
    while i < len(pezzi):
        frase = pezzi[i]
        fine = pezzi[i + 1] if i + 1 < len(pezzi) else ""
        if _AVVISO_SICUREZZA.search(frase):
            out.append(" " + ("\n" if fine == "\n" else ""))
        else:
            out.append(frase + fine)
        i += 2
    return "".join(out)


# ----------------------- MOTORE PRINCIPALE ----------------------- #

def phishing_analysis(
    headers: Dict[str, str],
    raw_text: str,
    urls: List[str],
    vt_dom: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Ritorna:
        {
          "score":  int 0-100,
          "level":  "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
          "reasons": [lista di stringhe]
        }
    """

    score = 0
    reasons: List[str] = []

    raw_low = raw_text.lower()
    subject = (headers.get("Subject") or headers.get("subject") or "").strip()
    subject_low = subject.lower()
    from_header = headers.get("From", "") or headers.get("from", "")
    from_display = (from_header.split("<", 1)[0]).lower()

    # Corpo DECODIFICATO (quoted-printable/base64/HTML): le parole chiave si cercano qui,
    # NON nel testo grezzo, che contiene header come "mx.google.com" e codifiche.
    try:
        body = extract_body(raw_text)
    except Exception:
        body = {"has_body": False, "text": "", "urls": [], "html_links": [], "forms": [], "attachments": []}
    body_low = _togli_avvisi_sicurezza(body["text"].lower())
    content_low = f"{subject_low}\n{from_display}\n{body_low}"
    urls = list(dict.fromkeys(list(urls or []) + body["urls"]))
    if not body["has_body"]:
        reasons.append("ℹ️ Corpo dell'email non presente: analisi solo su header/oggetto "
                       "(incolla il messaggio completo per un risultato affidabile).")

    # -------------------------------------------------------
    # 1) SPF / DKIM / DMARC FAIL (più pesanti)
    # -------------------------------------------------------
    if "spf=fail" in raw_low or "spf=softfail" in raw_low:
        score += 25
        reasons.append("SPF indica fail/softfail per il mittente.")

    if "dkim=fail" in raw_low:
        score += 20
        reasons.append("DKIM risulta FAIL nei risultati di autenticazione.")

    if "dmarc=fail" in raw_low or "dmarc=reject" in raw_low:
        score += 30
        reasons.append("DMARC risulta FAIL/REJECT per il dominio mittente.")

    # -------------------------------------------------------
    # 2) FROM vs RETURN-PATH / REPLY-TO (più aggressivo)
    # -------------------------------------------------------
    from_addr = _get_email_from_header(from_header)
    from_dom = _get_domain_from_email(from_addr)

    _root = dominio_registrabile   # eTLD+1: accounts.google.com -> google.com

    reply_dom = _get_domain_from_email(_get_email_from_header(headers.get("Reply-To", "")))
    if from_dom and reply_dom and not stessa_organizzazione(reply_dom, from_dom):
        sim = _similar(from_dom, reply_dom)
        score += 15  # già pesato negli header: qui solo come contesto, niente doppio conteggio
        reasons.append(
            f"Reply-To su altro dominio: le risposte vanno a '{reply_dom}' mentre il From è '{from_dom}' "
            f"(similarità {sim:.2f})."
        )

    rp_dom = _get_domain_from_email(_get_email_from_header(headers.get("Return-Path", "")))
    if from_dom and rp_dom and not stessa_organizzazione(rp_dom, from_dom):
        score += 5
        reasons.append(
            f"Return-Path su altro dominio ({rp_dom}): normale per newsletter, sospetto solo insieme ad altri segnali."
        )

    # Parole chiave (calcolate qui perché servono anche ai controlli su brand e link)
    def _trovate(parole: List[str]) -> List[str]:
        return [w for w in parole if re.search(rf"\b{re.escape(w)}\b", content_low)]

    urg = _trovate(URGENCY_KEYWORDS + ["entro 48 ore", "altrimenti", "ultimo avviso"])
    cred = _trovate(CREDENTIAL_KEYWORDS)
    inc = _trovate(INCIDENT_KEYWORDS)
    pay = _trovate(PAYMENT_KEYWORDS)
    # "intento sensibile": l'email chiede credenziali, parla di un problema all'account o di pagamenti.
    # Senza questo, citare un brand nel testo o avere link esterni è normale (newsletter, notizie).
    intento_sensibile = bool(cred or inc or pay)

    # Mittente legittimo AUTENTICATO: DMARC pass allineato al From (il dominio del From ha firmato/autorizzato).
    auth_low = (headers.get("Authentication-Results") or "").lower()
    m_hf = re.search(r"header\.from=([^\s;]+)", auth_low)
    dmarc_allineato = bool("dmarc=pass" in auth_low and m_hf is not None and from_dom
                           and dominio_registrabile(m_hf.group(1)) == dominio_registrabile(from_dom))
    # In alternativa al DMARC: firma DKIM valida di un dominio della stessa organizzazione del From
    # (molti mittenti legittimi non pubblicano una politica DMARC: dmarc=none)
    m_dk = re.search(r"dkim=pass[^;]*?header\.(?:d|i)=@?([^\s;]+)", auth_low)
    dkim_allineato = bool(m_dk and from_dom and "dmarc=fail" not in auth_low
                          and stessa_organizzazione(m_dk.group(1), from_dom))
    dmarc_allineato = dmarc_allineato or dkim_allineato
    massa = any(headers.get(h) for h in ("List-Unsubscribe", "List-Id")) or \
        (headers.get("Precedence", "").lower() in ("bulk", "list"))
    # Newsletter autenticata: le parole su password/attacchi sono probabilmente NOTIZIE, non richieste.
    # In questo caso il brand nel corpo e i link esterni non contano (oggetto e nome mittente sì).
    newsletter_autenticata = dmarc_allineato and massa
    intento_per_controlli = intento_sensibile and not newsletter_autenticata

    # -------------------------------------------------------
    # 3) BRAND IMPERSONATION
    # -------------------------------------------------------
    # Il brand conta se compare nel NOME del mittente o nell'OGGETTO; nel corpo solo se l'email
    # chiede credenziali/pagamenti (un articolo che cita Google non è un'impersonazione di Google).
    # nel corpo solo se il mittente non è autenticato: un mittente vero che cita un partner (es. Poste che
    # parla di cashback su Amazon) non sta impersonando quel brand
    testo_brand = f"{subject_low}\n{from_display}" + (
        f"\n{body_low}" if intento_per_controlli and not dmarc_allineato else "")
    for brand, official_roots in BRAND_OFFICIAL_DOMAINS.items():
        if re.search(rf"\b{re.escape(brand)}\b", testo_brand):
            # etichetta del dominio registrabile: accounts.google.com -> "google",
            # google-security-alert.com -> "google-security-alert" (NON ufficiale)
            from_root = etichetta(from_dom) if from_dom else ""
            ufficiale = bool(from_dom) and dominio_ufficiale_del_brand(from_dom, brand, official_roots)

            # dominio non ufficiale del brand → forte sospetto
            if from_dom and not ufficiale:
                score += 45
                reasons.append(
                    f"Possibile impersonazione del brand '{brand}': "
                    f"nome/oggetto/testo citano il brand ma il dominio mittente è '{from_dom}'."
                )
            elif not ufficiale:
                # typosquatting: dominio molto simile ma non uguale
                for root in official_roots:
                    sim = _similar(from_root, root)
                    if 0.70 <= sim < 1.0 and root not in from_root:
                        score += 30
                        reasons.append(
                            f"Possibile typosquatting per il brand '{brand}': "
                            f"dominio '{from_dom}' simile a '{root}.*' (sim={sim:.2f})."
                        )
                        break
            break  # analizza un brand alla volta

    # -------------------------------------------------------
    # 4) ANALISI URL / TLD / IP
    # -------------------------------------------------------
    link_diversi = 0
    domini_visti = set()
    for url in urls:
        dom = extract_domain(url)
        if dom in domini_visti and not IP_URL_RE.match(url):
            continue
        domini_visti.add(dom)
        info = analyze_domain(dom)
        tld = (info.get("tld") or "").lower()
        main_dom = info.get("main_domain", "")

        # IP diretto
        if IP_URL_RE.match(url):
            score += 30
            reasons.append(f"URL usa IP diretto invece di un dominio leggibile: {url}")
            continue

        # TLD sospetti
        if tld in SUSPICIOUS_TLDS:
            score += 20
            reasons.append(f"TLD sospetto per dominio nel link: .{tld}")

        # Dominio del link di un'ALTRA organizzazione rispetto al mittente.
        # Si confrontano i domini registrabili (eTLD+1) e le famiglie note:
        #   accounts.google.com vs myaccount.google.com / www.gstatic.com -> stessa organizzazione
        #   accounts.google.com vs google.com.evil.ru                     -> evil.ru: diverso
        # Conta solo se l'email ha un intento sensibile; social, font, standard (w3.org) sono neutri.
        if dmarc_allineato and link_tracciamento(dom):
            continue   # redirect di tracciamento della piattaforma di invio usata dal mittente autenticato
        if from_dom and dom and intento_per_controlli and not link_neutro(dom) and not stessa_organizzazione(dom, from_dom):
            sim = _similar(etichetta(from_dom), etichetta(dom))
            if sim < 0.5 and link_diversi < 20:
                peso = 10 if sim < 0.3 else 5
                link_diversi += peso
                score += peso
                reasons.append(
                    f"Dominio del link '{dom}' diverso dal dominio del mittente '{from_dom}' (sim={sim:.2f})."
                )

    # Link ingannevole: il testo mostra un dominio, l'href porta altrove
    link_ingannevole = False
    for href, testo in body["html_links"]:
        t = testo.strip().lower()
        if t.startswith(("http://", "https://", "www.")):
            d_testo = extract_domain(t if "//" in t else "http://" + t)
            d_href = extract_domain(href)
            if dmarc_allineato and link_tracciamento(d_href) and stessa_organizzazione(d_testo, from_dom):
                continue   # testo = sito del mittente, href = tracciamento clic della sua piattaforma di invio
            if d_testo and d_href and not stessa_organizzazione(d_testo, d_href):
                score += 30
                reasons.append(f"Link ingannevole: il testo mostra '{d_testo}' ma porta a '{d_href}'.")
                link_ingannevole = True
                break
    if body["forms"]:
        score += 25
        reasons.append("L'email contiene un modulo HTML (form) per inserire dati.")

    # -------------------------------------------------------
    # 5) KEYWORDS (urgenza, credenziali) – più peso alle credenziali
    # -------------------------------------------------------
    punti_notifica = score            # per calcolare quanto pesano le sole parole "da notifica"
    if urg:
        score += 15 if intento_sensibile else 6
        reasons.append(f"Oggetto/testo contiene espressioni di forte urgenza: {', '.join(urg[:3])}.")
    if cred:
        score += 25
        reasons.append(f"Oggetto/testo parla di password/credenziali/reset account: {', '.join(cred[:3])}.")
    if inc:
        score += 20
        reasons.append(f"Allarme di sicurezza / minaccia sull'account: {', '.join(inc[:3])}.")
    if pay:
        score += 20
        reasons.append(f"Richiesta legata a pagamenti/coordinate bancarie: {', '.join(pay[:3])}.")
    if (cred or inc) and urls:
        score += 15
        reasons.append("Combinazione tipica: richiesta su password/account + link da cliccare.")
    punti_notifica = score - punti_notifica - (20 if pay else 0)

    bec_trovate = []
    for nome, pattern, peso in BEC_RULES:
        m = re.search(pattern, content_low)
        if m:
            score += peso
            bec_trovate.append(nome)
            reasons.append(f"{nome}: «{m.group(0)}».")
            if nome.startswith(("Invito", "Segretezza", "Scadenza")):
                punti_notifica += peso

    # Mittente legittimo AUTENTICATO (DMARC pass allineato al From) che manda notifiche o newsletter:
    # - notifiche: tutti i link (esclusi social/font/standard) verso la stessa organizzazione
    # - newsletter: header List-Unsubscribe/List-Id (invio di massa dichiarato)
    # -> le parole "da notifica" (password, sicurezza, urgenza, "clicca qui") pesano il 60% in meno.
    # NON si attenua: pagamenti/IBAN/gift card, richiesta di disattivare protezioni, link ingannevoli,
    # form, brand impersonato, threat feed (una casella vera compromessa resta pericolosa).
    link_rilevanti = [u for u in urls if not link_neutro(extract_domain(u))
                      and not (dmarc_allineato and link_tracciamento(extract_domain(u)))]
    link_interni = bool(from_dom) and all(stessa_organizzazione(extract_domain(u), from_dom) for u in link_rilevanti)
    if punti_notifica > 0 and dmarc_allineato and (link_interni or massa) and not body["forms"] and not link_ingannevole:
        riduzione = int(punti_notifica * (0.75 if massa else 0.6))
        score -= riduzione
        tipo = "link solo verso la stessa organizzazione" if link_interni else "invio di massa dichiarato (newsletter)"
        reasons.append(f"ℹ️ Mittente autenticato (DMARC/DKIM allineati a {dominio_registrabile(from_dom)}), {tipo}: "
                       f"peso delle parole chiave ridotto (-{riduzione}).")
    sensibile = pay or any(n.startswith(("Gift", "Cambio coordinate", "Richiesta di dati")) for n in bec_trovate)
    pressione = urg or any(n.startswith(("Scoraggia", "Segretezza", "Scadenza")) for n in bec_trovate)
    if sensibile and pressione:
        score += 15
        reasons.append("Combinazione tipica BEC: richiesta sensibile (pagamenti/dati) + pressione o segretezza.")

    # -------------------------------------------------------
    # 6) VirusTotal (se presente)
    # -------------------------------------------------------
    if isinstance(vt_dom, dict):
        stats = vt_dom.get("stats", {}) or {}
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        reputation = vt_dom.get("reputation", 0)

        if malicious > 0:
            score += 40
            reasons.append(
                f"VirusTotal segnala {malicious} motori che classificano il dominio come MALICIOUS."
            )
        elif suspicious > 0:
            score += 25
            reasons.append(
                f"VirusTotal segnala {suspicious} motori che classificano il dominio come SUSPICIOUS."
            )

        if reputation < 0:
            score += 15
            reasons.append(f"Reputation globale negativa su VirusTotal ({reputation}).")

    # -------------------------------------------------------
    # NORMALIZZAZIONE + LIVELLO
    # -------------------------------------------------------
    score = max(0, min(100, score))
    level = _classify_level(score)

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "body_analyzed": body["has_body"],
        "urls": urls,
        "attachments": body["attachments"],
    }


# -------------------------- FORMAT REPORT -------------------------- #

def format_phishing_summary(result: Dict[str, Any]) -> str:
    score = int(result.get("score", 0))
    level = result.get("level") or _classify_level(score)
    reasons: List[str] = result.get("reasons", [])

    lines: List[str] = []
    lines.append(f"Phishing score: {score}/100")
    lines.append(f"Phishing risk level: {level}")

    if not reasons:
        lines.append("Nessun forte indicatore di phishing rilevato.")
    else:
        lines.append("Indicatori rilevati:")
        for r in reasons:
            lines.append(f"- {r}")

    return "\n".join(lines)


   