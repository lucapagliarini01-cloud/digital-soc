# analyzer/soc_risk.py
"""
SOC Risk Score unico, usato sia dalla GUI sia dalla CLI.

Prima: 0.5 * header + 0.5 * VirusTotal, con VirusTotal assente = 50 "neutro"
→ qualsiasi email senza dati VT finiva a 25/100 MEDIUM e il phishing non contava.

Ora:
- si parte dal segnale più forte tra header e phishing (contenuto/URL),
  più un quarto dell'altro (due fonti concordi = rischio più alto);
- VirusTotal AGGIUNGE rischio solo se segnala qualcosa; se manca non inventa nulla;
- SPF/DKIM/DMARC pass non riducono il rischio (dicono chi ha spedito, non se è innocuo).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional


def vt_bonus(vt_results: Iterable[Optional[Dict[str, Any]]]) -> tuple[int, str]:
    """Bonus 0-40 dal risultato VirusTotal peggiore (solo status == 'ok')."""
    peggiore_mal, peggiore_sus = 0, 0
    for vt in vt_results:
        if not isinstance(vt, dict) or vt.get("status") != "ok":
            continue
        st = vt.get("stats", {}) or {}
        peggiore_mal = max(peggiore_mal, int(st.get("malicious", 0) or 0))
        peggiore_sus = max(peggiore_sus, int(st.get("suspicious", 0) or 0))
    if peggiore_mal >= 3:
        return 40, f"VirusTotal: {peggiore_mal} motori malicious"
    if peggiore_mal >= 1:
        return 25, f"VirusTotal: {peggiore_mal} motore/i malicious"
    if peggiore_sus >= 1:
        return 10, f"VirusTotal: {peggiore_sus} motore/i suspicious"
    return 0, ""


def livello(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def intel_bonus(corrispondenze: Iterable[Any] = (), eta_domini: Dict[str, Optional[int]] | None = None,
                segnali_locali: int = 0) -> tuple[int, List[str]]:
    """
    Bonus 0-50 dalla threat intel open-source:
      - URL esatto in un feed di phishing: +45 (prova molto forte)
      - dominio in un feed: +35
      - IP in blocklist: +15
      - dominio registrato da < 30 giorni: +20 solo se ci sono già altri segnali, altrimenti +5
    """
    motivi: List[str] = []
    bonus = 0
    tipi = {getattr(c, "tipo", None) or c.get("tipo") for c in corrispondenze}
    fonti = sorted({getattr(c, "fonte", None) or c.get("fonte") for c in corrispondenze})
    if "url" in tipi:
        bonus = max(bonus, 45)
    if "dominio" in tipi:
        bonus = max(bonus, 35)
    if "ip" in tipi:
        bonus = max(bonus, 15)
    if fonti:
        motivi.append("Presente in threat feed: " + ", ".join(fonti))
    for dom, eta in (eta_domini or {}).items():
        if eta is not None and eta < 30:
            extra = 20 if segnali_locali >= 15 else 5
            bonus += extra
            motivi.append(f"Dominio {dom} registrato da {eta} giorni")
            break
    return min(bonus, 50), motivi


def compute_soc_risk(header_score: int, phishing_score: int,
                     vt_results: Iterable[Optional[Dict[str, Any]]] = (),
                     intel: int = 0, intel_reasons: Optional[List[str]] = None) -> Dict[str, Any]:
    h = max(0, min(100, int(header_score or 0)))
    p = max(0, min(100, int(phishing_score or 0)))
    base = max(h, p) + min(h, p) // 4
    bonus, motivo_vt = vt_bonus(vt_results)
    score = max(0, min(100, base + bonus + int(intel or 0)))
    return {
        "score": score,
        "level": livello(score),
        "header": h,
        "phishing": p,
        "vt_bonus": bonus,
        "vt_reason": motivo_vt,
        "intel_bonus": int(intel or 0),
        "intel_reasons": list(intel_reasons or []),
    }


def format_soc_risk(r: Dict[str, Any], body_analyzed: bool = True) -> str:
    righe = [
        f"SOC Risk Score: {r['score']}/100",
        f"Overall SOC Risk: {r['level']}",
        f"  (header {r['header']} · phishing {r['phishing']}"
        + (f" · VirusTotal +{r['vt_bonus']}" if r.get("vt_bonus") else "")
        + (f" · threat intel +{r['intel_bonus']}" if r.get("intel_bonus") else "")
        + (f" – {r['vt_reason']}" if r.get("vt_reason") else "") + ")",
    ]
    for m in r.get("intel_reasons", []):
        righe.append(f"  • {m}")
    if not body_analyzed:
        righe.append("⚠️ Valutazione PARZIALE: analizzati solo gli header. "
                     "Incolla l'email completa (Gmail: ⋮ → Mostra originale) prima di considerarla sicura.")
    return "\n".join(righe)
