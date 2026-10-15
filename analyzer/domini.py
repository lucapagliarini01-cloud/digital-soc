# analyzer/domini.py
"""
Confronto corretto tra domini: dominio registrabile (eTLD+1) e famiglie di domini ufficiali.

Perché serve: confrontare la PRIMA etichetta ("accounts" di accounts.google.com) con il dominio
di un link ("myaccount", "gstatic") dava falsi allarmi su email Google autentiche, mentre un
confronto per sottostringa ("google" in "google-security-alert.com") lasciava passare i falsi.

    dominio_registrabile("accounts.google.com")   -> "google.com"
    dominio_registrabile("google.com.evil.ru")    -> "evil.ru"
    dominio_registrabile("posta.example.co.uk")   -> "example.co.uk"
    stessa_organizzazione("accounts.google.com", "www.gstatic.com") -> True
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Optional

# Suffissi pubblici a più livelli più comuni (usati se tldextract non è installato)
_SUFFISSI_MULTIPLI = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp",
    "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co", "com.tr", "com.cn", "com.hk", "com.tw",
    "com.sg", "com.my", "co.in", "net.in", "org.in", "co.za", "co.kr", "co.id", "co.il", "com.ua",
    "gov.it", "edu.it", "com.es", "com.pt", "com.pl", "com.ru", "com.sa", "com.eg",
    "github.io", "blogspot.com", "herokuapp.com", "appspot.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "netlify.app", "vercel.app", "azurewebsites.net", "cloudfront.net",
    "s3.amazonaws.com", "r2.dev", "onrender.com",
}

# Domini registrabili che appartengono alla stessa organizzazione (infrastruttura, CDN, alias)
FAMIGLIE: dict[str, set[str]] = {
    "google": {"google.com", "google.it", "gmail.com", "googlemail.com", "gstatic.com", "googleapis.com",
               "googleusercontent.com", "ggpht.com", "youtube.com", "ytimg.com", "youtu.be", "goo.gl",
               "withgoogle.com", "googlegroups.com", "g.co", "google.co.uk", "googleadservices.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "outlook.com",
                  "live.com", "hotmail.com", "msn.com", "sharepoint.com", "onedrive.com", "1drv.ms",
                  "aka.ms", "skype.com", "windows.net", "azure.com", "bing.com", "msauth.net", "msftauth.net",
                  "microsoft365.com", "teams.microsoft.com", "sfx.ms", "linkedin.com", "licdn.com", "lnkd.in"},
    "apple": {"apple.com", "icloud.com", "me.com", "mac.com", "apple.news", "mzstatic.com", "itunes.com"},
    "amazon": {"amazon.com", "amazon.it", "amazon.de", "amazon.fr", "amazon.es", "amazon.co.uk",
               "media-amazon.com", "ssl-images-amazon.com", "amazonaws.com", "primevideo.com", "a2z.com",
               "amazonses.com", "amazonmusic.com", "audible.it", "audible.com"},
    "paypal": {"paypal.com", "paypal.it", "paypal.me", "paypalobjects.com", "paypal-communication.com"},
    "meta": {"facebook.com", "fb.com", "facebookmail.com", "instagram.com", "whatsapp.com", "fbcdn.net",
             "meta.com", "messenger.com"},
    "poste": {"poste.it", "posteitaliane.it", "postepay.it", "bancopostaimpresa.it"},
    "rcs": {"rcsmediagroup.it", "corriere.it", "corriereobjects.it", "gazzetta.it", "rcs.it", "iodonna.it",
            "oggi.it", "amica.it", "cook.corriere.it", "solferino.it"},
    "dhl": {"dhl.com", "dhl.it", "dhl.de", "dhlparcel.it"},
}
_DOMINIO_A_FAMIGLIA = {d: nome for nome, ds in FAMIGLIE.items() for d in ds}


@lru_cache(maxsize=1)
def _estrattore():
    """tldextract con la Public Suffix List inclusa nel pacchetto (nessun download)."""
    try:
        import tldextract
        return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    except Exception:
        return None


def _pulisci(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    if h.startswith("[") or h.count(":") > 1:      # IPv6
        return h.strip("[]")
    return h.split(":", 1)[0]


@lru_cache(maxsize=20000)
def dominio_registrabile(host: str) -> str:
    h = _pulisci(host)
    if not h:
        return ""
    try:
        ipaddress.ip_address(h)
        return h                                     # un IP resta un IP
    except ValueError:
        pass
    ex = _estrattore()
    if ex is not None:
        r = ex(h)
        if r.domain and r.suffix:
            return f"{r.domain}.{r.suffix}"
        # suffisso non presente nella Public Suffix List (.local, .lan, .example, .invalid…):
        # si usa il calcolo manuale, altrimenti "a.local" e "b.local" sembrerebbero lo stesso dominio
    parti = h.split(".")
    if len(parti) <= 2:
        return h
    if ".".join(parti[-2:]) in _SUFFISSI_MULTIPLI:
        return ".".join(parti[-3:])
    if ".".join(parti[-3:]) in _SUFFISSI_MULTIPLI:
        return ".".join(parti[-4:])
    return ".".join(parti[-2:])


def etichetta(host: str) -> str:
    """Nome senza suffisso del dominio registrabile: accounts.google.com -> 'google'."""
    reg = dominio_registrabile(host)
    ex = _estrattore()
    if ex is not None:
        r = ex(reg)
        if r.domain and r.suffix:
            return r.domain
    return reg.split(".")[0]


def famiglia(host: str) -> Optional[str]:
    return _DOMINIO_A_FAMIGLIA.get(dominio_registrabile(host))


def stessa_organizzazione(a: str, b: str) -> bool:
    ra, rb = dominio_registrabile(a), dominio_registrabile(b)
    if not ra or not rb:
        return False
    if ra == rb:
        return True
    fa = _DOMINIO_A_FAMIGLIA.get(ra)
    return fa is not None and fa == _DOMINIO_A_FAMIGLIA.get(rb)


def dominio_ufficiale_del_brand(host: str, brand: str, radici: list[str]) -> bool:
    """True se host appartiene davvero al brand (famiglia nota o etichetta esatta, es. amazon.it)."""
    reg = dominio_registrabile(host)
    if reg in FAMIGLIE.get(brand, set()):
        return True
    return etichetta(host) in radici


# Link "neutri": standard tecnici, social nel piè di pagina, store di app, font.
# Non indicano phishing se puntano altrove rispetto al mittente (restano comunque controllati nei threat feed).
DOMINI_NEUTRI = {
    "w3.org", "schema.org", "purl.org", "xmlsoap.org", "openxmlformats.org", "ietf.org",
    "facebook.com", "fb.com", "instagram.com", "x.com", "twitter.com", "linkedin.com", "youtube.com",
    "youtu.be", "tiktok.com", "pinterest.com", "pinterest.it", "threads.net", "whatsapp.com", "wa.me",
    "t.me", "telegram.me", "spotify.com", "medium.com", "bsky.app",
}
HOST_NEUTRI = {"fonts.googleapis.com", "fonts.gstatic.com", "apps.apple.com", "itunes.apple.com",
               "play.google.com", "maps.google.com", "google.com"}


def link_neutro(host: str) -> bool:
    h = _pulisci(host)
    h = h[4:] if h.startswith("www.") else h
    return h in HOST_NEUTRI or dominio_registrabile(h) in DOMINI_NEUTRI


# Piattaforme di invio email (ESP): riscrivono i link per contare i clic. Un link che passa da qui
# NON è ingannevole se l'email è autenticata dal mittente (resta comunque controllato nei threat feed).
DOMINI_TRACCIAMENTO = {
    "marketingusercontent.com", "pb-dynmktg.com", "pb-dynmktge.com", "dynmktg.com",          # Microsoft Dynamics
    "list-manage.com", "mailchi.mp", "mcusercontent.com", "mcsv.net",                        # Mailchimp
    "sendgrid.net", "mandrillapp.com", "mailgun.org", "sparkpostmail.com", "awstrack.me",    # SendGrid, Mandrill, Mailgun, SES
    "exacttarget.com", "exct.net", "sfmc-content.com", "pardot.com",                          # Salesforce
    "hubspotlinks.com", "hubspotemail.net", "hs-analytics.net",                               # HubSpot
    "rs6.net", "klclick.com", "klclick1.com", "klclick2.com", "klaviyomail.com",              # Constant Contact, Klaviyo
    "sendibt2.com", "sendibt3.com", "sendibm1.com", "r.sb", "mjt.lu", "mailjet.com",           # Brevo, Mailjet
    "mlsend.com", "mailerlite.com", "ck.page", "convertkit-mail.com", "convertkit-mail2.com",  # MailerLite, ConvertKit
    "emarsys.net", "dmtrk.net", "createsend.com", "createsend1.com", "cmail19.com", "cmail20.com",
    "acemlna.com", "acemlnb.com", "acemlnc.com", "en25.com", "mktomail.com", "mkto-sj310056.com",
    "selligent.com", "slgnt.eu", "substack.com", "getresponse.com", "gr-cdn.com", "mailup.it", "mailupclient.com",
    "nl.mailant.it", "mailant.it", "4dem.it", "voxmail.it", "musvc.com", "ec-cluster.com",
}


def link_tracciamento(host: str) -> bool:
    h = _pulisci(host)
    return dominio_registrabile(h) in DOMINI_TRACCIAMENTO or any(h == d or h.endswith("." + d) for d in DOMINI_TRACCIAMENTO)

