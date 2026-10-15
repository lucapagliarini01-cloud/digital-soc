"""Test isolati: configurazione e dati in una cartella temporanea, mai in quella dell'utente."""
import os
import tempfile
from pathlib import Path

_TMP = Path(tempfile.mkdtemp(prefix="digitalsoc-test-"))
os.environ["XDG_CONFIG_HOME"] = str(_TMP / "config")
os.environ["XDG_DATA_HOME"] = str(_TMP / "data")
CARTELLA_TEST = _TMP
