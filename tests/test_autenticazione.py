#!/usr/bin/env python3
"""
Test: SPF/DKIM/DMARC "pass" contano solo da server fidati o con firma DKIM verificata da noi.

    python -m unittest tests/test_autenticazione.py -v
"""
import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tests  # noqa: E402,F401

from analyzer import autenticazione as AU  # noqa: E402
from analyzer.pipeline import analizza_email  # noqa: E402

CORPO = ("From: Banca <avvisi@banca.example>\nTo: a@b.it\nSubject: Estratto conto\n"
         "Message-ID: <m1@banca.example>\nDate: Mon, 12 Oct 2026 10:00:00 +0000\n"
         "Content-Type: text/plain\n\nIl tuo estratto conto di ottobre e' disponibile nell'area clienti.\n")


def con_ar(ar):
    return f"Authentication-Results: {ar}\n" + CORPO


class TestAuthservId(unittest.TestCase):
    def test_estrazione(self):
        self.assertEqual(AU.authserv_id("mx.google.com; spf=pass smtp.mailfrom=x"), "mx.google.com")
        self.assertEqual(AU.authserv_id("spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x; dkim=pass"), "")
        self.assertEqual(AU.authserv_id(""), "")

    def test_suffisso_senza_inganni(self):
        self.assertTrue(AU.server_fidato("mx.google.com"))
        self.assertTrue(AU.server_fidato("mx-12.mx.google.com"))
        self.assertFalse(AU.server_fidato("mx.google.com.attaccante.example"))
        self.assertFalse(AU.server_fidato("fakegoogle.com"))
        self.assertFalse(AU.server_fidato(""))
        self.assertTrue(AU.server_fidato("mx.azienda.example", ["azienda.example"]))


class TestFiducia(unittest.TestCase):
    def test_pass_falsi_ignorati(self):
        falsa = con_ar("mx.attaccante.example; spf=pass smtp.mailfrom=banca.example; "
                       "dkim=pass header.d=banca.example; dmarc=pass header.from=banca.example")
        vera = con_ar("mx.google.com; spf=pass smtp.mailfrom=banca.example; "
                      "dkim=pass header.d=banca.example; dmarc=pass header.from=banca.example")
        rf, rv = analizza_email(falsa, whois_attivo=False), analizza_email(vera, whois_attivo=False)
        self.assertTrue(rf["autenticazione"]["pass_ignorati"])
        self.assertFalse(rv["autenticazione"]["pass_ignorati"])
        self.assertTrue(any("non verificabile" in i for i in rf["header_issues"]))
        self.assertIn("dmarc=pass", rf["auth"], "nel report resta l'header originale")

    def test_fail_contano_sempre(self):
        r = analizza_email(con_ar("mx.attaccante.example; spf=fail; dkim=fail; dmarc=fail header.from=banca.example"),
                           whois_attivo=False)
        self.assertTrue(any("DMARC FAIL" in i for i in r["header_issues"]))
        self.assertGreaterEqual(r["header_score"], 60)

    def test_mittente_fidato_ma_pass_falso(self):
        from analyzer import fidati as F
        F.aggiungi("banca.example", "test")
        try:
            falsa = con_ar("mx.attaccante.example; dkim=pass header.d=banca.example; dmarc=pass header.from=banca.example")
            self.assertEqual(analizza_email(falsa, whois_attivo=False)["fidato"], "fidato_non_autenticato")
            vera = con_ar("mx.google.com; dkim=pass header.d=banca.example; dmarc=pass header.from=banca.example")
            self.assertEqual(analizza_email(vera, whois_attivo=False)["fidato"], "fidato")
        finally:
            F.rimuovi("banca.example")


class TestDKIM(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import dkim  # noqa: F401
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
        except ImportError:
            raise unittest.SkipTest("dkimpy non installato")
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption())
        pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.txt = b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)

    def firmata(self, testo=CORPO):
        import dkim
        dati = testo.replace("\n", "\r\n").encode()
        firma = dkim.sign(dati, b"sel1", b"banca.example", self.priv, include_headers=[b"from", b"subject", b"to"])
        return (firma + dati).decode().replace("\r\n", "\n")

    def dns(self, nome, timeout=5):
        return self.txt if nome.startswith(b"sel1._domainkey.banca.example") else b""

    def test_firma_valida_e_manomessa(self):
        raw = self.firmata()
        self.assertEqual(AU.verifica_dkim(raw, self.dns), (True, "banca.example"))
        manomessa = raw.replace("ottobre", "novembre")
        self.assertFalse(AU.verifica_dkim(manomessa, self.dns)[0])

    def test_dkim_verificato_rende_autentica(self):
        raw = "Authentication-Results: mx.sconosciuto.example; dkim=pass header.d=banca.example\n" + self.firmata()
        h, info = AU.valuta({"Authentication-Results": "mx.sconosciuto.example; dkim=pass header.d=banca.example"},
                            raw, dkim_attivo=True, dnsfunc=self.dns)
        self.assertTrue(info["dkim_verificato"])
        self.assertIn("dkim=pass (verificata da Digital SOC) header.d=banca.example", h["Authentication-Results"])
        self.assertIn("dkim=nonverificato", h["Authentication-Results"], "il pass dichiarato resta ignorato")


if __name__ == "__main__":
    unittest.main()
