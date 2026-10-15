#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
write_report.py – Salvataggio report TXT per Digital SOC

Questa utility NON genera il contenuto del report:
si limita a salvarlo su disco in un file di testo.
Include supporto ai nuovi moduli (es. PDF/JS analyzer)
aggiungendo automaticamente separatori puliti e leggibili.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional


def _decorate_section(title: str) -> str:
    """
    Rende più leggibile ogni sezione del report.
    """
    bar = "=" * len(title)
    return f"{bar}\n{title}\n{bar}\n"


def write_report(
    content: str,
    filename: Optional[str] = None,
    directory: Optional[str] = None,
) -> str:
    """
    Salva il contenuto del report in un file TXT.

    Parametri:
        content   : stringa già formattata del report.
        filename  : nome file (es. 'report_soc_test.txt').
                    Se None, viene generato automaticamente.
        directory : cartella in cui salvare il file.
                    - None  -> usa la cartella di lavoro corrente (Path.cwd()).
                    - str   -> percorso della cartella (creata se non esiste).

    Ritorna:
        Percorso completo del file come stringa, oppure "" in caso di errore.
    """

    if not content:
        print("[ERRORE] write_report: contenuto del report vuoto, niente da salvare.")
        return ""

    # Detecta se esistono le nuove sezioni (es. PDF)
    final_content = ""

    # Spezza sezioni per rendere il report più leggibile
    sections = content.strip().split("\n\n")
    for sec in sections:
        if sec.strip().startswith("==="):
            # aggiunge titolo decorato
            title = sec.strip().replace("=", "").strip()
            final_content += _decorate_section(title) + "\n"
        final_content += sec.strip() + "\n\n"

    # Cartella destinazione
    base_dir = Path(directory) if directory else Path.cwd()

    try:
        base_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[ERRORE] Impossibile creare la cartella dei report '{base_dir}': {e}")
        return ""

    # Nome file automatico
    if filename is None:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"report_soc_{timestamp}.txt"

    report_path = base_dir / filename

    try:
        # il report contiene mittenti, oggetti e IOC: leggibile solo da te (dove il sistema lo permette)
        import os
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(final_content)
        try:
            os.chmod(report_path, 0o600)
        except OSError:
            pass

        print(f"[+] Report SOC salvato: {report_path}")
        return str(report_path)

    except Exception as e:
        print(f"[ERRORE] Impossibile salvare il report TXT '{report_path}': {e}")
        return ""

