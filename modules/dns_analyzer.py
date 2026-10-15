"""
dns_analyzer.py
---------------
Módulo de análisis de registros DNS básicos.

Consulta los registros más importantes de un dominio (A, AAAA, MX, NS, TXT)
y detecta si están configuradas las políticas de email SPF y DMARC.

Requiere: dnspython  →  pip install dnspython
"""

from __future__ import annotations

import re

import dns.exception
import dns.resolver

# ── Tiempo máximo de espera por consulta DNS (segundos) ───────────────────────
TIMEOUT = 5

# Políticas DMARC válidas según RFC 7489
DMARC_POLICIES = {"none", "quarantine", "reject"}


# ══════════════════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def analyze_dns(domain: str) -> dict:
    """
    Consulta los registros DNS de un dominio y detecta SPF y DMARC.

    Args:
        domain: Dominio objetivo sin esquema (ej. 'ejemplo.com').

    Returns:
        Diccionario con todos los registros encontrados y flags de SPF/DMARC.
    """
    if not domain or not domain.strip():
        return _empty_result(domain, error="El dominio no puede estar vacío.")

    domain = domain.strip().lower()
    result = _empty_result(domain, error=None)

    # ── Consultamos cada tipo de registro ──────────────────────────────────────
    result["a_records"]    = _query(domain, "A")
    result["aaaa_records"] = _query(domain, "AAAA")
    result["mx_records"]   = _query(domain, "MX")
    result["ns_records"]   = _query(domain, "NS")
    result["txt_records"]  = _query(domain, "TXT")

    # ── SPF: registro TXT que empieza por "v=spf1" ─────────────────────────────
    for txt in result["txt_records"]:
        if txt.lower().startswith("v=spf1"):
            result["spf_found"]  = True
            result["spf_record"] = txt
            result["spf_all"]    = parse_spf_all(txt)
            break

    # ── DMARC: se publica en _dmarc.<dominio>, no en el dominio principal ─────
    for txt in _query(f"_dmarc.{domain}", "TXT"):
        if txt.lower().startswith("v=dmarc1"):
            result["dmarc_found"]  = True
            result["dmarc_record"] = txt
            result["dmarc_policy"] = parse_dmarc_policy(txt)
            break

    # ── Error general: no se encontró ningún registro ─────────────────────────
    if not result["a_records"] and not result["aaaa_records"] and not result["ns_records"]:
        result["error"] = (
            "No se encontraron registros DNS para este dominio. "
            "Comprueba que el dominio existe y es accesible."
        )

    return result


def parse_dmarc_policy(record: str) -> str | None:
    """Extrae la política p= de un registro DMARC ('none', 'quarantine' o 'reject')."""
    match = re.search(r"(?:^|;)\s*p\s*=\s*([a-z]+)", record.lower())
    if match and match.group(1) in DMARC_POLICIES:
        return match.group(1)
    return None


def parse_spf_all(record: str) -> str | None:
    """
    Devuelve el mecanismo 'all' final del SPF: '-all' (estricto), '~all' (suave),
    '?all' (neutro) o '+all' (permite a cualquiera: muy peligroso).
    """
    match = re.search(r"([+\-~?]?)all\b", record.lower())
    if not match:
        return None
    return (match.group(1) or "+") + "all"


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS PRIVADOS
# ══════════════════════════════════════════════════════════════════════════════

def _query(name: str, record_type: str) -> list[str]:
    """
    Realiza una consulta DNS y devuelve los resultados como lista de strings.

    Si la consulta falla (dominio inexistente, timeout, tipo no disponible...)
    devuelve una lista vacía: la app nunca se rompe por un fallo DNS.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(name, record_type)
        return [_format_record(r, record_type) for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        return []
    except dns.exception.DNSException:
        return []


def _format_record(record, record_type: str) -> str:
    """Convierte un registro de dnspython en texto legible según su tipo."""
    if record_type == "MX":
        return f"{record.preference} {record.exchange.to_text().rstrip('.')}"
    if record_type == "TXT":
        # Los registros TXT pueden venir fragmentados en varios strings
        return b"".join(record.strings).decode("utf-8", errors="replace")
    return record.to_text().rstrip(".")


def _empty_result(domain: str, error: str | None) -> dict:
    """Resultado base, vacío."""
    return {
        "domain":       domain,
        "a_records":    [],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "txt_records":  [],
        "spf_found":    False,
        "spf_record":   None,
        "spf_all":      None,
        "dmarc_found":  False,
        "dmarc_record": None,
        "dmarc_policy": None,
        "error":        error,
    }
