# analyzer/pipeline.py
"""
Analisi STRUTTURATA di un'email (usata dal monitor IMAP e dalla dashboard).

Riusa i moduli esistenti (headers, urls, phishing, soc_risk) e sostituisce
VirusTotal con threat intel open-source controllata in locale (threatfeeds).
Restituisce un dizionario con punteggi, motivi, IOC e il report in testo e HTML.
"""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import html
import ipaddress
import re
from datetime import datetime, timezone
from email import message_from_string
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, List, Optional

from .autenticazione import valuta as valuta_autenticazione
from .email_body import extract_body
from .headers import detect_suspicious_headers, parse_headers, risk_score
from .phishing import format_phishing_summary, phishing_analysis
from . import fidati
from .soc_risk import compute_soc_risk, format_soc_risk, intel_bonus, livello
from .threatfeeds import ThreatFeeds, dnsbl
from .urls import extract_urls, unique_domains

_WHOIS_CACHE: Dict[str, Optional[int]] = {}


def _root(dom: str) -> str:
    from .domini import dominio_registrabile
    return dominio_registrabile(dom)


def defang(s: str) -> str:
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def eta_dominio(dominio: str, timeout: float = 12.0) -> Optional[int]:
    """Giorni dalla registrazione (python-whois, open-source). None se non disponibile."""
    dominio = _root(dominio)
    if dominio in _WHOIS_CACHE:
        return _WHOIS_CACHE[dominio]

    def _q():
        import whois
        w = whois.whois(dominio)
        cd = w.get("creation_date") if hasattr(w, "get") else getattr(w, "creation_date", None)
        if isinstance(cd, list):
            cd = min([d for d in cd if isinstance(d, datetime)], default=None)
        if not isinstance(cd, datetime):
            return None
        if cd.tzinfo is None:
            cd = cd.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - cd).days

    with cf.ThreadPoolExecutor(max_workers=1) as ex:
        try:
            eta = ex.submit(_q).result(timeout=timeout)
        except Exception:
            eta = None
    _WHOIS_CACHE[dominio] = eta
    return eta


def _ip_origine(raw: str) -> str:
    """Ultimo IP pubblico nella catena Received (il più vicino al mittente)."""
    msg = message_from_string(raw.replace("\r\n", "\n").lstrip("\n"))
    pubblici: List[str] = []
    for r in msg.get_all("Received", []) or []:
        for ip in re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)\]", str(r), re.I):
            try:
                if ipaddress.ip_address(ip).is_global and ip not in pubblici:
                    pubblici.append(ip)
            except ValueError:
                pass
    return pubblici[-1] if pubblici else ""


def analizza_email(raw: str, feeds: Optional[ThreatFeeds] = None, whois_attivo: bool = True,
                   soglia_whois: int = 15, dnsbl_resolver: Optional[str] = None,
                   usa_dnsbl: bool = False, hibp=None, troncata_byte: int = 0,
                   auth_fidati=(), verifica_dkim: bool = False, campagne=None) -> Dict[str, Any]:
    """troncata_byte > 0: l'email era oltre il limite di dimensione e sono stati scaricati solo gli header."""
    raw = (raw or "").replace("\r\n", "\n").lstrip("﻿").lstrip("\n")
    headers = parse_headers(raw)
    auth_originale = headers.get("Authentication-Results", "")
    # SPF/DKIM/DMARC "pass" valgono solo se scritti da un server di fiducia o se la firma DKIM la verifichiamo noi
    headers, info_auth = valuta_autenticazione(headers, raw, auth_fidati, verifica_dkim)
    issues = detect_suspicious_headers(headers)
    if info_auth["nota"]:
        issues.append(info_auth["nota"])
    h_score = risk_score(issues)
    body = extract_body(raw)
    urls = extract_urls(raw)
    domini_link = unique_domains(urls)

    nome_from, addr_from = (getaddresses([headers.get("From", "")]) or [("", "")])[0]
    addr_from = addr_from.lower()
    dom_from = addr_from.rsplit("@", 1)[-1] if "@" in addr_from else ""
    reply_to = (getaddresses([headers.get("Reply-To", "")]) or [("", "")])[0][1].lower()
    ip_orig = _ip_origine(raw)

    phish = phishing_analysis(headers, raw, urls, None)

    # ---- threat intel open-source (locale) ----
    corr = []
    if feeds is not None:
        corr = feeds.controlla(urls=urls, domini=[d for d in [dom_from] + domini_link if d],
                               ips=[ip_orig] if ip_orig else [])
    dnsbl_note = ""
    if usa_dnsbl:
        try:
            corr += dnsbl(ip_orig or None, _root(dom_from) if dom_from else None, dnsbl_resolver)
        except Exception as e:
            dnsbl_note = str(e)

    eta: Dict[str, Optional[int]] = {}
    locali = max(h_score, phish["score"])
    if whois_attivo and (locali >= soglia_whois or corr):
        for d in list(dict.fromkeys([_root(x) for x in [dom_from] + domini_link[:2] if x]))[:3]:
            eta[d] = eta_dominio(d)

    bonus, motivi_intel = intel_bonus(corr, eta, segnali_locali=locali)
    soc = compute_soc_risk(h_score, phish["score"], [], intel=bonus, intel_reasons=motivi_intel)

    # ---- limiti di dimensione/complessità: analisi parziale, e di per sé un segnale ----
    motivi_limiti: List[str] = []
    extra = 0
    if troncata_byte:
        motivi_limiti.append(f"⚠️ Email di {troncata_byte / 1048576:.0f} MB oltre il limite: analizzati solo gli header "
                             "(le email enormi sono anche un modo per eludere i controlli).")
        extra += 15
    if body.get("limiti"):
        motivi_limiti.append("⚠️ Email insolitamente complessa, analisi parziale: " + "; ".join(body["limiti"]) + ".")
        extra += 10
    if extra:
        soc = dict(soc, score=min(100, soc["score"] + extra))
        soc["level"] = livello(soc["score"])

    # ---- campagne ATTIVE segnalate dalla community (ThreatFox, OTX): priorità maggiorata ----
    hit_campagne: List[Dict[str, Any]] = []
    motivi_campagne: List[str] = []
    if campagne is not None:
        try:
            hit_campagne = campagne.controlla(
                urls=urls, domini=[d for d in [dom_from] + domini_link if d], ips=[ip_orig] if ip_orig else [],
                sha256=[a["sha256"] for a in body["attachments"] if a.get("sha256")],
                email=[x for x in (addr_from, reply_to) if x])
        except Exception:
            hit_campagne = []
        if hit_campagne:
            from .campagne import bonus as bonus_campagne
            minimo = bonus_campagne(hit_campagne)
            if soc["score"] < minimo:
                soc = dict(soc, score=minimo)
                soc["level"] = livello(minimo)
            for nome in dict.fromkeys(h["nome"] for h in hit_campagne):
                ind = [h for h in hit_campagne if h["nome"] == nome]
                motivi_campagne.append(f"🚨 Campagna attiva segnalata dalla community: {nome} – "
                                       + ", ".join(f"{h['tipo']} {h['valore']}" for h in ind[:3]))

    # ---- mittenti fidati (allowlist dell'utente) ----
    fiducia, motivo_fiducia = None, None
    voce = fidati.cerca(addr_from, dom_from)
    if voce:
        au = fidati.autenticazione(headers.get("Authentication-Results", ""), dom_from)
        motivi_ph = phish.get("reasons", [])
        duri = []
        if corr or hit_campagne:
            duri.append("presente nei threat feed / in una campagna attiva")
        if any("Link ingannevole" in x for x in motivi_ph):
            duri.append("link ingannevole")
        if any("modulo HTML" in x for x in motivi_ph):
            duri.append("modulo per inserire dati")
        if any("REPLY-TO MISMATCH" in i for i in issues):
            duri.append("risposte dirottate su un altro dominio")
        # chiede credenziali/pagamenti E porta fuori dal dominio del mittente (tipico di casella compromessa)
        from .domini import link_neutro, stessa_organizzazione
        sensibile = any(x.startswith(("Oggetto/testo parla di password", "Richiesta legata a pagamenti",
                                      "Cambio coordinate", "Gift card")) for x in motivi_ph)
        from .domini import link_tracciamento
        esterni = [d for d in domini_link if not link_neutro(d) and not stessa_organizzazione(d, dom_from)
                   and not (au["autenticato"] and link_tracciamento(d))]
        newsletter = any(headers.get(h) for h in ("List-Unsubscribe", "List-Id"))   # parla di notizie, non chiede
        if sensibile and esterni and not newsletter:
            duri.append(f"chiede credenziali/pagamenti con link verso {esterni[0]}")
        if au["autenticato"] and not duri:
            fiducia = "fidato"
            soc = dict(soc, score=min(soc["score"], 10))
            soc["level"] = livello(soc["score"])
            motivo_fiducia = f"✅ Mittente fidato ({voce}) e autenticato: considerato non sospetto."
        elif not au["autenticato"]:
            fiducia = "fidato_non_autenticato"
            soc = dict(soc, score=min(100, soc["score"] + 15))
            soc["level"] = livello(soc["score"])
            motivo_fiducia = (f"⚠️ Il mittente risulta {voce} (tra i fidati) ma l'email NON è autenticata da quel "
                              f"dominio: possibile falsificazione del mittente.")
        else:
            fiducia = "fidato_con_segnali"
            motivo_fiducia = f"⚠️ Mittente fidato ({voce}) ma con segnali gravi: {', '.join(duri)}."

    # ---- Have I Been Pwned: violazioni note del dominio mittente (contesto, NON cambia il punteggio) ----
    hibp_ctx, hibp_nota = None, None
    if hibp is not None and dom_from:
        try:
            ctx = hibp.contesto(dom_from)
        except Exception:
            ctx = None
        if ctx:
            from .hibp import nota_mittente
            aut = fidati.autenticazione(headers.get("Authentication-Results", ""), dom_from)["autenticato"]
            hibp_nota = nota_mittente(ctx, aut)
            v = ctx["violazioni"]
            hibp_ctx = {"dominio": ctx["dominio"], "nomi": [b["Name"] for b in v], "recenti": ctx["recenti"],
                        "password": ctx["password"], "autenticato": aut,
                        "ultima": {k: v[0].get(k) for k in ("Name", "Title", "BreachDate", "PwnCount")}}
            if ctx["recenti"] and not aut:
                hibp_nota = hibp_nota.replace("ℹ️", "⚠️", 1)

    # ---- data del messaggio ----
    try:
        data_msg = parsedate_to_datetime(headers.get("Date", "")).astimezone(timezone.utc).isoformat()
    except Exception:
        data_msg = None

    # ---- IOC ----
    malevoli = {c.valore for c in corr} | {h["valore"] for h in hit_campagne}
    iocs: List[Dict[str, Any]] = []
    for u in urls:
        iocs.append({"tipo": "url", "valore": u, "malevolo": u in malevoli})
    for d in domini_link:
        iocs.append({"tipo": "dominio", "valore": d, "malevolo": d in malevoli})
    if dom_from:
        iocs.append({"tipo": "dominio_mittente", "valore": dom_from, "malevolo": dom_from in malevoli})
    if addr_from:
        iocs.append({"tipo": "mittente", "valore": addr_from, "malevolo": False})
    if reply_to and reply_to != addr_from:
        iocs.append({"tipo": "reply_to", "valore": reply_to, "malevolo": False})
    if ip_orig:
        iocs.append({"tipo": "ip", "valore": ip_orig, "malevolo": ip_orig in malevoli})
    for a in body["attachments"]:
        if a.get("sha256"):
            iocs.append({"tipo": "sha256", "valore": a["sha256"], "malevolo": False, "nota": a["name"]})

    # motivi principali, dal più forte (per Telegram e per l'elenco)
    motivi = motivi_campagne + ([motivo_fiducia] if motivo_fiducia else []) + motivi_limiti + [m for m in motivi_intel]
    motivi += [i for i in issues if not i.startswith("ℹ️")]
    motivi += [r for r in phish.get("reasons", []) if not r.startswith("ℹ️")]
    if hibp_nota and hibp_nota.startswith("⚠️"):
        motivi.append(hibp_nota)

    risultato = {
        "analizzato_il": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "message_id": headers.get("Message-ID", "").strip(),
        "sha256": hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest(),
        "data": data_msg,
        "from_nome": nome_from,
        "from": addr_from,
        "from_dominio": dom_from,
        "reply_to": reply_to,
        "to": headers.get("To", ""),
        "subject": headers.get("Subject", ""),
        "ip_origine": ip_orig,
        "auth": auth_originale,
        "autenticazione": info_auth,
        "header_issues": issues,
        "header_score": h_score,
        "phishing": {k: v for k, v in phish.items() if k != "attachments"},
        "allegati": body["attachments"],
        "urls": urls,
        "domini_link": domini_link,
        "campagne": hit_campagne,
        "intel": {"corrispondenze": [c.to_dict() for c in corr]
                  + [{"fonte": f"Campagna: {h['nome']}", "tipo": h["tipo"], "valore": h["valore"], "voce": h["id"]}
                     for h in hit_campagne], "eta_domini": eta,
                  "motivi": motivi_intel, "dnsbl_nota": dnsbl_note},
        "soc": soc,
        "fidato": fiducia,
        "hibp": hibp_ctx,
        "hibp_nota": hibp_nota,
        "score": soc["score"],
        "livello": soc["level"],
        "corpo_presente": phish.get("body_analyzed", True) and not troncata_byte,
        "limiti": body.get("limiti", []) + (["solo header: email oltre il limite"] if troncata_byte else []),
        "motivi": motivi,
        "iocs": iocs,
        "anteprima": body["text"][:600],
    }
    risultato["report_testo"] = report_testo(risultato)
    return risultato


# ------------------------------------------------------------------ report
def report_testo(r: Dict[str, Any]) -> str:
    out = ["=== DIGITAL SOC - EMAIL ANALYZER ===",
           f"Analizzato: {r['analizzato_il']}",
           f"Da: {r['from_nome']} <{r['from']}>",
           f"Reply-To: {r['reply_to'] or '-'}",
           f"Oggetto: {r['subject']}",
           f"Data: {r['data'] or '-'}",
           f"Message-ID: {r['message_id'] or '-'}",
           f"IP di origine: {r['ip_origine'] or '-'}",
           "", "=== HEADER ANALYSIS ==="]
    out += [f"- {i}" for i in r["header_issues"]] or ["Nessun problema evidente negli header."]
    out.append(f"Header risk score: {r['header_score']}/100")
    out += ["", "=== URL ANALYSIS ==="]
    if r["urls"]:
        out.append(f"URL trovati ({len(r['urls'])}) – mostrati disattivati, NON visitati:")
        out += [f"  - {defang(u)}" for u in r["urls"][:40]]
    else:
        out.append("Nessun URL trovato.")
    out += ["", "=== ALLEGATI ==="]
    out += [f"  - {a['name']} ({a['content_type']}, {a['size']} byte) SHA256 {a['sha256']}"
            for a in r["allegati"]] or ["Nessun allegato."]
    out += ["", "=== THREAT INTEL (open-source, controllo locale) ==="]
    if r["intel"]["corrispondenze"]:
        for c in r["intel"]["corrispondenze"]:
            out.append(f"  ⚠ {c['fonte']}: {c['tipo']} {defang(c['valore'])}")
    else:
        out.append("Nessuna corrispondenza nei feed.")
    for d, e in r["intel"]["eta_domini"].items():
        out.append(f"  WHOIS {d}: " + (f"registrato da {e} giorni" if e is not None else "età non disponibile"))
    if r["intel"]["dnsbl_nota"]:
        out.append(f"  DNSBL: {r['intel']['dnsbl_nota']}")
    if r.get("hibp_nota"):
        out += ["", "=== HAVE I BEEN PWNED (violazioni note del mittente) ===", r["hibp_nota"],
                "  (contesto: non modifica il punteggio)"]
    out += ["", "=== PHISHING ANALYSIS ===", format_phishing_summary(r["phishing"]).rstrip()]
    out += ["", "=== SOC FINAL RISK SCORE ===", format_soc_risk(r["soc"], body_analyzed=r["corpo_presente"])]
    return "\n".join(out) + "\n"


COLORI = {"LOW": "#2ea043", "MEDIUM": "#d29922", "HIGH": "#f0883e", "CRITICAL": "#f85149"}


def report_html(r: Dict[str, Any], firma: str = "") -> str:
    e = html.escape
    col = COLORI.get(r["livello"], "#888")
    righe_ioc = "".join(
        f"<tr><td>{e(i['tipo'])}</td><td class='mono'>{e(defang(i['valore']) if i['tipo'] in ('url', 'dominio', 'dominio_mittente') else i['valore'])}</td>"
        f"<td>{'⚠ in feed' if i.get('malevolo') else ''}</td></tr>" for i in r["iocs"])
    motivi = "".join(f"<li>{e(m)}</li>" for m in r["motivi"][:15]) or "<li>Nessun indicatore rilevante</li>"
    return f"""<!doctype html><html lang="it"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Report email – {e(r['subject'][:80])}</title>
<style>
:root{{--bg:#0f1115;--card:#171a21;--fg:#e6e6e6;--mut:#9aa4b2;--bd:#2a2f3a}}
body{{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Cantarell,sans-serif;background:var(--bg);color:var(--fg);line-height:1.5}}
main{{max-width:980px;margin:0 auto;padding:24px 16px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px;margin:14px 0}}
.badge{{display:inline-block;padding:6px 14px;border-radius:999px;background:{col};color:#fff;font-weight:700}}
h1{{font-size:22px;margin:0 0 6px}} h2{{font-size:16px;color:var(--mut);margin:0 0 10px;text-transform:uppercase;letter-spacing:.04em}}
table{{width:100%;border-collapse:collapse}} td{{padding:6px 8px;border-top:1px solid var(--bd);vertical-align:top;word-break:break-all}}
.mono,pre{{font-family:ui-monospace,"DejaVu Sans Mono",monospace;font-size:13px}}
pre{{white-space:pre-wrap;word-wrap:break-word;margin:0}} .mut{{color:var(--mut)}}
</style></head><body><main>
<div class="card"><span class="badge">{e(r['livello'])} · {r['score']}/100</span>
<h1 style="margin-top:12px">{e(r['subject'] or '(senza oggetto)')}</h1>
<div class="mut">Da {e(r['from_nome'])} &lt;{e(r['from'])}&gt; · {e(r['data'] or '')}</div></div>
<div class="card"><h2>Motivi principali</h2><ul>{motivi}</ul></div>
<div class="card"><h2>Indicatori (IOC)</h2><table>{righe_ioc or '<tr><td>Nessuno</td></tr>'}</table></div>
<div class="card"><h2>Report completo</h2><pre>{e(r['report_testo'])}</pre></div>
<p class="mut">Generato da Digital SOC – Email Analyzer. URL e domini sono disattivati (hxxp, [.]) per evitare clic accidentali. {e(firma)}</p>
</main></body></html>"""
