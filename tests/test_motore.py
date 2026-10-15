#!/usr/bin/env python3
"""
Test del motore di analisi (nessuna rete).

    python -m unittest discover -s tests -t . -v
"""
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tests  # noqa: E402,F401  (configurazione isolata in una cartella temporanea)

from analyzer import email_body as EB  # noqa: E402
from analyzer.pipeline import analizza_email  # noqa: E402

CAMPIONI = Path(__file__).parent / "campioni"
ATTESI = {
    "google_avviso_legittimo.eml": "LOW",
    "google_falso.eml": "CRITICAL",
    "legittima_newsletter.eml": "LOW",
    "newsletter_corriere.eml": "LOW",
    "newsletter_giornale.eml": "LOW",
    "newsletter_lavoro.eml": "LOW",
    "phishing_cambio_password.eml": "CRITICAL",
    "poste_payandwin.eml": "MEDIUM",
}
TESTA = ("From: Mario <mario@esempio.it>\nTo: a@b.it\nSubject: Prova\nMessage-ID: <x@esempio.it>\n"
         "Date: Mon, 12 Oct 2026 10:00:00 +0000\nMIME-Version: 1.0\n")


def analizza(raw):
    return analizza_email(raw, whois_attivo=False)


class TestCampioni(unittest.TestCase):
    def test_livelli(self):
        for nome, atteso in ATTESI.items():
            r = analizza((CAMPIONI / nome).read_text(errors="replace"))
            self.assertEqual(r["livello"], atteso, f"{nome}: {r['score']} {r['motivi'][:3]}")

    def test_link_disattivati_nel_report(self):
        r = analizza((CAMPIONI / "phishing_cambio_password.eml").read_text(errors="replace"))
        self.assertNotIn("https://", r["report_testo"].split("=== URL ANALYSIS ===")[1].split("===")[0])


class TestLimiti(unittest.TestCase):
    def test_troppe_parti(self):
        corpo = "".join(f"--B\nContent-Type: text/plain\n\nparte {i}\n" for i in range(EB.MAX_PARTI + 50))
        r = analizza(TESTA + 'Content-Type: multipart/mixed; boundary="B"\n\n' + corpo + "--B--\n")
        self.assertTrue(any("parti MIME" in x for x in r["limiti"]))

    def test_troppi_link(self):
        link = "".join(f'<a href="https://sito{i}.esempio.it/">x</a>' for i in range(EB.MAX_URL + 100))
        r = analizza(TESTA + f"Content-Type: text/html\n\n<html><body>{link}</body></html>\n")
        self.assertEqual(len(r["urls"]), EB.MAX_URL)

    def test_testo_enorme_senza_punteggiatura(self):
        inizio = time.time()
        analizza(TESTA + "Content-Type: text/plain\n\n" + "mai " * 500_000 + "\n")
        self.assertLess(time.time() - inizio, 30)

    def test_solo_header(self):
        r = analizza_email(TESTA + "\n", whois_attivo=False, troncata_byte=40 * 1048576)
        self.assertFalse(r["corpo_presente"])
        self.assertGreaterEqual(r["score"], 15)


if __name__ == "__main__":
    unittest.main()
