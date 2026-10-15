# Digital SOC – Email Analyzer

[![tests](https://github.com/lucapagliarini01-cloud/digital-soc/actions/workflows/tests.yml/badge.svg)](https://github.com/lucapagliarini01-cloud/digital-soc/actions/workflows/tests.yml)

Analizza un'email sospetta (`.eml`) e restituisce un **punteggio di rischio spiegato**: ogni punto ha un motivo.

🇬🇧 [English version](README.md)

![Panoramica](docs/screenshots/panoramica.png)

## Cosa controlla

- **Autenticazione**: SPF, DKIM e DMARC contano solo se scritti da un server di ricezione fidato
  o se la firma DKIM viene verificata crittograficamente. Un "pass" non è mai sinonimo di email sicura.
- **Corpo e link**: decodifica del testo e dell'HTML, link reali confrontati con il testo mostrato,
  moduli, allegati con SHA-256. Nessun link aperto, nessun allegato eseguito.
- **Phishing e BEC**: urgenza, richieste di credenziali o pagamenti, cambio IBAN, gift card, brand imitati.
- **Threat intel open-source** confrontata in locale: i dati delle email non escono dal PC.

| Elenco delle email | Dettaglio con motivi e IOC |
|---|---|
| ![Email](docs/screenshots/email.png) | ![Dettaglio](docs/screenshots/dettaglio.png) |

Gli screenshot usano solo email sintetiche di laboratorio.

## Uso

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
python main.py --aggiorna-feed     # threat feed (consigliato)
python main.py email.eml           # report a schermo e in TXT
python main.py email.eml --html    # anche in HTML
```

Codice di uscita: 0 LOW, 1 MEDIUM, 2 HIGH, 3 CRITICAL.

## Test

```bash
python -m unittest discover -s tests -t . -v
```

Usalo solo su email che hai il diritto di analizzare.
