#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Digital SOC – CLI

    python main.py email.eml                # report a schermo + salvataggio TXT
    python main.py email.eml --html         # salva anche il report HTML
    python main.py email.eml --no-whois     # senza WHOIS (più veloce, offline)
    python main.py                          # usa text_headers.txt
    python main.py --aggiorna-feed          # scarica i threat feed open-source (una volta al giorno basta)

Stesso motore del monitor: header, corpo decodificato, URL, allegati, phishing,
threat feed open-source (controllo locale) e SOC Risk Score.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyzer.pdf_js_analyzer import check_pdf_for_js  # noqa: E402
from analyzer.pipeline import analizza_email, report_html  # noqa: E402
from analyzer.threatfeeds import ThreatFeeds  # noqa: E402
from analyzer.write_report import write_report  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Digital SOC – analisi di un'email sospetta")
    ap.add_argument("file", nargs="?", default="text_headers.txt", help=".eml o file di testo con header/email")
    ap.add_argument("--pdf", help="PDF allegato da controllare per JavaScript")
    ap.add_argument("--html", action="store_true", help="salva anche il report HTML")
    ap.add_argument("--no-whois", action="store_true")
    ap.add_argument("--no-salva", action="store_true", help="non salvare il report TXT")
    ap.add_argument("--aggiorna-feed", action="store_true", help="scarica i threat feed e termina")
    ap.add_argument("--no-dkim", action="store_true", help="non verificare la firma DKIM via DNS")
    ap.add_argument("--server-fidato", action="append", default=[], metavar="HOST",
                    help="server di ricezione di cui fidarsi per Authentication-Results (es. mx.azienda.it)")
    args = ap.parse_args()

    feeds = ThreatFeeds(Path("~/.local/share/digitalsoc/feed").expanduser())
    if args.aggiorna_feed:
        feeds.aggiorna(forza=True, log=print)
        return 0
    raw = Path(args.file).read_text(encoding="utf-8", errors="replace")
    feeds.carica()
    if not any(v["voci"] for v in feeds.riepilogo().values()):
        print("ℹ️  Threat feed non ancora scaricati: python main.py --aggiorna-feed\n")

    r = analizza_email(raw, feeds=feeds, whois_attivo=not args.no_whois,
                       auth_fidati=args.server_fidato, verifica_dkim=not args.no_dkim)
    testo = r["report_testo"]

    if args.pdf:
        has_js, info = check_pdf_for_js(args.pdf)
        testo += ("\n=== PDF / ATTACHMENT ANALYSIS (JS CHECK) ===\n"
                  f"File analizzato: {args.pdf}\n"
                  + ("[ALTO RISCHIO] PDF con marker JavaScript/azioni automatiche.\n" if has_js else "[OK] Nessun JavaScript nel PDF.\n")
                  + info + "\n")

    print(testo)
    if not args.no_salva:
        write_report(testo)
    if args.html:
        p = Path(f"report_{r['sha256'][:12]}.html")
        p.write_text(report_html(r), encoding="utf-8")
        print(f"[+] Report HTML salvato: {p.resolve()}")
    # codice di uscita utile negli script: 0 LOW, 1 MEDIUM, 2 HIGH, 3 CRITICAL
    return ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(r["livello"])


if __name__ == "__main__":
    sys.exit(main())
