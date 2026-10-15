# analyzer/threatfeeds.py
"""
Threat intelligence OPEN-SOURCE al posto di VirusTotal.

Le liste vengono scaricate periodicamente e controllate IN LOCALE:
nessun URL/dominio delle tue email viene inviato a servizi esterni.

Feed predefiniti (gratuiti, senza chiave):
  - OpenPhish Community Feed (URL di phishing, aggiornato ogni 12 ore)
  - Phishing.Database (domini e link di phishing attivi, licenza MIT)
Opzionali:
  - URLhaus (abuse.ch): richiede una Auth-Key gratuita, URL configurabile
  - qualunque altro feed testuale (un URL/dominio/IP per riga) aggiunto in config
  - liste locali: blocklist.txt / allowlist.txt scritte da te
  - Spamhaus DBL/ZEN via DNS (solo con resolver proprio, non con 8.8.8.8/1.1.1.1)
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set
from urllib.parse import urlsplit

FEED_PREDEFINITI = [
    {"nome": "OpenPhish", "tipo": "url",
     "url": "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"},
    {"nome": "Phishing.Database domini", "tipo": "dominio",
     "url": "https://phish.co.za/latest/phishing-domains-ACTIVE.txt",
     "mirror": ["https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"]},
    {"nome": "Phishing.Database link", "tipo": "url",
     "url": "https://phish.co.za/latest/phishing-links-ACTIVE.txt",
     "mirror": ["https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"]},
]

MAX_FEED = 100 * 1024 * 1024        # dimensione massima di un feed scaricato

# Domini enormi e condivisi: non vanno mai marcati come malevoli per dominio intero
# (i feed contengono URL specifici ospitati su questi servizi; li confrontiamo solo come URL esatti)
DOMINI_CONDIVISI = {
    "google.com", "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle",
    "microsoft.com", "sharepoint.com", "onedrive.live.com", "1drv.ms", "office.com",
    "github.com", "githubusercontent.com", "github.io", "dropbox.com", "dropboxusercontent.com",
    "wetransfer.com", "we.tl", "box.com", "amazonaws.com", "cloudfront.net", "azureedge.net",
    "windows.net", "web.app", "firebaseapp.com", "appspot.com", "pages.dev", "workers.dev",
    "netlify.app", "vercel.app", "weebly.com", "wixsite.com", "blogspot.com", "notion.site",
    "canva.com", "linkedin.com", "facebook.com", "instagram.com", "t.me", "telegram.org",
    "bit.ly", "tinyurl.com", "youtube.com", "apple.com", "icloud.com", "adobe.com",
}


def normalizza_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
    except ValueError:
        return ""
    host = (p.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    path = p.path.rstrip("/") or ""
    q = ("?" + p.query) if p.query else ""
    return f"{host}{path}{q}"


def host_di(u: str) -> str:
    if "://" not in u:
        u = "http://" + u
    try:
        h = (urlsplit(u).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def _antenati(host: str) -> List[str]:
    """a.b.c.example.com -> [a.b.c.example.com, b.c.example.com, c.example.com, example.com]"""
    parti = host.split(".")
    return [".".join(parti[i:]) for i in range(len(parti) - 1)]


@dataclass
class Corrispondenza:
    fonte: str
    tipo: str        # url | dominio | ip
    valore: str      # cosa avevamo nell'email
    voce: str        # cosa c'era nel feed

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ThreatFeeds:
    cartella: Path
    feed: List[dict] = field(default_factory=lambda: list(FEED_PREDEFINITI))
    ore_aggiornamento: float = 6.0
    timeout: float = 30.0
    _url: Dict[str, Set[str]] = field(default_factory=dict)      # fonte -> url normalizzati
    _dom: Dict[str, Set[str]] = field(default_factory=dict)      # fonte -> domini
    _ip: Dict[str, Set[str]] = field(default_factory=dict)
    allow: Set[str] = field(default_factory=set)
    stato: Dict[str, dict] = field(default_factory=dict)

    def __post_init__(self):
        self.cartella = Path(self.cartella).expanduser()
        self.cartella.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------ download
    def _file(self, nome: str) -> Path:
        return self.cartella / (re.sub(r"[^\w.-]+", "_", nome) + ".txt")

    def aggiorna(self, forza: bool = False, log=print) -> None:
        """Scarica i feed scaduti. Se la rete non c'è, usa le copie già salvate."""
        try:
            import requests
        except ImportError:
            log("[feed] requests non installato: uso solo le copie locali")
            requests = None
        for f in self.feed:
            dest = self._file(f["nome"])
            eta_ore = (time.time() - dest.stat().st_mtime) / 3600 if dest.exists() else 1e9
            if not forza and eta_ore < self.ore_aggiornamento:
                continue
            if requests is None:
                continue
            # URL principale e poi i mirror, finché uno funziona
            errori = []
            for url in [f["url"]] + list(f.get("mirror", [])):
                try:
                    with requests.get(url, timeout=self.timeout, stream=True,
                                      headers={"User-Agent": "DigitalSOC-EmailAnalyzer/2.0 (uso difensivo)"}) as r:
                        if r.status_code != 200:
                            raise RuntimeError(f"HTTP {r.status_code}")
                        pezzi, letti = [], 0
                        for pezzo in r.iter_content(1 << 16):     # al massimo MAX_FEED byte: un feed
                            letti += len(pezzo)                    # gonfiato non riempie disco e memoria
                            if letti > MAX_FEED:
                                raise ValueError(f"feed oltre {MAX_FEED >> 20} MB")
                            pezzi.append(pezzo)
                    testo = b"".join(pezzi).decode("utf-8", errors="replace")
                    if len(testo) < 20:
                        raise ValueError("feed vuoto")
                    tmp = dest.with_suffix(".tmp")
                    tmp.write_text(testo, encoding="utf-8")
                    tmp.replace(dest)
                    origine = "" if url == f["url"] else " (mirror)"
                    log(f"[feed] {f['nome']}: aggiornato{origine} ({testo.count(chr(10))} righe)")
                    break
                except Exception as e:
                    host = urlsplit(url).hostname
                    errori.append(f"{host}: {e if isinstance(e, (RuntimeError, ValueError)) else e.__class__.__name__}")
            else:
                copia = ("uso copia del " + time.strftime('%d/%m %H:%M', time.localtime(dest.stat().st_mtime))
                         if dest.exists() else "nessuna copia locale")
                log(f"[feed] {f['nome']}: download non riuscito ({'; '.join(errori)}); {copia}")
        self.carica()

    def carica(self) -> None:
        self._url, self._dom, self._ip, self.stato = {}, {}, {}, {}
        for f in self.feed:
            dest = self._file(f["nome"])
            if dest.exists():
                self._carica_righe(f["nome"], f.get("tipo", "url"), dest.read_text(encoding="utf-8", errors="replace"))
                self.stato[f["nome"]] = {"voci": self._conta(f["nome"]),
                                         "aggiornato": time.strftime("%Y-%m-%d %H:%M", time.localtime(dest.stat().st_mtime))}
            else:
                self.stato[f["nome"]] = {"voci": 0, "aggiornato": None}
        # liste locali dell'utente
        bl = self.cartella / "blocklist.txt"
        if bl.exists():
            self._carica_righe("Blocklist locale", "auto", bl.read_text(encoding="utf-8"))
            self.stato["Blocklist locale"] = {"voci": self._conta("Blocklist locale"), "aggiornato": "locale"}
        al = self.cartella / "allowlist.txt"
        self.allow = set()
        if al.exists():
            self.allow = {r.strip().lower().lstrip("*.") for r in al.read_text().splitlines()
                          if r.strip() and not r.startswith("#")}

    def _conta(self, nome: str) -> int:
        return len(self._url.get(nome, ())) + len(self._dom.get(nome, ())) + len(self._ip.get(nome, ()))

    def _carica_righe(self, nome: str, tipo: str, testo: str) -> None:
        u, d, ip = self._url.setdefault(nome, set()), self._dom.setdefault(nome, set()), self._ip.setdefault(nome, set())
        for riga in testo.splitlines():
            riga = riga.strip()
            if not riga or riga[0] in "#;!":
                continue
            riga = riga.split()[0].split(",")[0].strip('"')
            t = tipo
            if t == "auto":
                t = "url" if "/" in riga else ("ip" if _is_ip(riga) else "dominio")
            if t == "ip" or _is_ip(riga):
                ip.add(riga)
            elif t == "dominio":
                d.add(riga.lower().lstrip("*.").rstrip("."))
            else:
                n = normalizza_url(riga)
                if n:
                    u.add(n)

    # ------------------------------------------------------------ controlli
    def _consentito(self, host: str) -> bool:
        return any(a in self.allow for a in _antenati(host)) if host else False

    def controlla(self, urls: Iterable[str] = (), domini: Iterable[str] = (),
                  ips: Iterable[str] = ()) -> List[Corrispondenza]:
        trovati: List[Corrispondenza] = []
        visti = set()

        def add(c: Corrispondenza):
            k = (c.fonte, c.tipo, c.valore)
            if k not in visti:
                visti.add(k)
                trovati.append(c)

        for url in urls:
            n = normalizza_url(url)
            h = host_di(url)
            if not n or self._consentito(h):
                continue
            for fonte, insieme in self._url.items():
                if n in insieme:
                    add(Corrispondenza(fonte, "url", url, n))
            # dominio dell'URL nelle liste di domini (mai per servizi condivisi)
            for ant in _antenati(h):
                if ant in DOMINI_CONDIVISI:
                    break
                for fonte, insieme in self._dom.items():
                    if ant in insieme:
                        add(Corrispondenza(fonte, "dominio", h, ant))
            if _is_ip(h):
                for fonte, insieme in self._ip.items():
                    if h in insieme:
                        add(Corrispondenza(fonte, "ip", h, h))
        for dom in domini:
            dom = dom.lower()
            if not dom or self._consentito(dom):
                continue
            for ant in _antenati(dom):
                if ant in DOMINI_CONDIVISI:
                    break
                for fonte, insieme in self._dom.items():
                    if ant in insieme:
                        add(Corrispondenza(fonte, "dominio", dom, ant))
                # host presenti come URL "nudi" nei feed di URL (es. phishing-sito.example/)
                for fonte, insieme in self._url.items():
                    if ant in insieme:
                        add(Corrispondenza(fonte, "dominio", dom, ant))
        for ip in ips:
            for fonte, insieme in self._ip.items():
                if ip in insieme:
                    add(Corrispondenza(fonte, "ip", ip, ip))
        return trovati

    def riepilogo(self) -> Dict[str, dict]:
        return dict(self.stato)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- DNSBL (opzionale)
def dnsbl(ip: Optional[str], dominio: Optional[str], resolver_ip: Optional[str] = None,
          zone_ip: str = "zen.spamhaus.org", zone_dom: str = "dbl.spamhaus.org") -> List[Corrispondenza]:
    """
    Spamhaus via DNS. Funziona SOLO con un resolver proprio (es. unbound locale):
    con i DNS pubblici Spamhaus risponde 127.255.255.254 = "query rifiutata".
    """
    out: List[Corrispondenza] = []
    try:
        import dns.resolver
    except ImportError:
        return out
    res = dns.resolver.Resolver()
    if resolver_ip:
        res.nameservers = [resolver_ip]
    res.lifetime = 5

    def q(nome: str) -> List[str]:
        try:
            return [r.to_text() for r in res.resolve(nome, "A")]
        except Exception:
            return []

    if ip and _is_ip(ip) and ipaddress.ip_address(ip).version == 4:
        risposte = q(".".join(reversed(ip.split("."))) + "." + zone_ip)
        if any(r.startswith("127.255.255.") for r in risposte):
            raise RuntimeError("Spamhaus rifiuta il resolver in uso: configura un resolver proprio")
        if any(r.startswith("127.0.0.") for r in risposte):
            out.append(Corrispondenza("Spamhaus ZEN", "ip", ip, ",".join(risposte)))
    if dominio:
        risposte = q(f"{dominio}.{zone_dom}")
        if any(r.startswith("127.255.255.") for r in risposte):
            raise RuntimeError("Spamhaus rifiuta il resolver in uso: configura un resolver proprio")
        if any(r.startswith("127.0.1.") for r in risposte):
            out.append(Corrispondenza("Spamhaus DBL", "dominio", dominio, ",".join(risposte)))
    return out


def salva_stato_json(feeds: ThreatFeeds, percorso: Path) -> None:
    percorso.write_text(json.dumps(feeds.riepilogo(), indent=2))
