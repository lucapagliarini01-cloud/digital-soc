# pdf_js_analyzer.py
"""
Analisi base dei PDF per rilevare riferimenti a JavaScript o azioni automatiche.

Versione "furba":
- non fa parsing avanzato
- cerca marker tipici nei byte del file

Se troviamo /JavaScript, /JS, /AA o /OpenAction
segnaliamo il PDF come potenzialmente pericoloso.
"""

from pathlib import Path
from typing import Tuple

# Marker tipici usati nei PDF con azioni/script
JS_MARKERS = [b"/JavaScript", b"/JS", b"/AA", b"/OpenAction"]


def check_pdf_for_js(pdf_path: str) -> Tuple[bool, str]:
    """
    Ritorna (has_js, info_text)

    has_js: True se troviamo marker sospetti
    info_text: breve spiegazione da usare nel report
    """
    pdf_file = Path(pdf_path)

    if not pdf_file.exists():
        return False, f"File PDF non trovato: {pdf_path}"

    try:
        data = pdf_file.read_bytes()
    except Exception as e:
        return False, f"Impossibile leggere il PDF ({e})"

    found_markers = [m for m in JS_MARKERS if m in data]

    if found_markers:
        # Convertiamo i marker trovati in stringhe leggibili
        markers_str = ", ".join(m.decode("ascii", errors="ignore") for m in found_markers)
        info = (
            f"Trovati marker PDF legati a JavaScript o azioni automatiche: {markers_str}. "
            f"Potrebbe trattarsi di un PDF con comportamento dinamico (possibile vettore di attacco)."
        )
        return True, info

    return False, "Nessun marker tipico di JavaScript rilevato nel PDF."
