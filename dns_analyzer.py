"""
dns_analyzer.py
---------------
Módulo de análisis de registros DNS básicos.

Consulta los registros más importantes de un dominio (A, AAAA, MX, NS, TXT)
y detecta si están configuradas las políticas de email SPF y DMARC.

Requiere: dnspython  →  pip install dnspython
"""

import dns.resolver
import dns.exception


# ── Tiempo máximo de espera por consulta DNS (segundos) ───────────────────────
TIMEOUT = 5


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

    # ── Validación básica ──────────────────────────────────────────────────────
    if not domain or not domain.strip():
        return _empty_result(domain, error="El dominio no puede estar vacío.")

    domain = domain.strip().lower()

    # ── Resultado base ─────────────────────────────────────────────────────────
    result = {
        "domain":       domain,
        "a_records":    [],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "txt_records":  [],
        "spf_found":    False,
        "dmarc_found":  False,
        "dmarc_record": None,
        "error":        None,
    }

    # ── Consultamos cada tipo de registro ──────────────────────────────────────

    result["a_records"]    = _query(domain, "A")
    result["aaaa_records"] = _query(domain, "AAAA")
    result["mx_records"]   = _query(domain, "MX")
    result["ns_records"]   = _query(domain, "NS")
    result["txt_records"]  = _query(domain, "TXT")

    # ── Detectar SPF en los registros TXT ─────────────────────────────────────
    # SPF siempre empieza por "v=spf1"
    for txt in result["txt_records"]:
        if txt.lower().startswith("v=spf1"):
            result["spf_found"] = True
            break

    # ── Detectar DMARC consultando _dmarc.<dominio> ───────────────────────────
    # DMARC se publica en un subdominio especial, no en el dominio principal
    dmarc_records = _query(f"_dmarc.{domain}", "TXT")

    for txt in dmarc_records:
        if txt.lower().startswith("v=dmarc1"):
            result["dmarc_found"]  = True
            result["dmarc_record"] = txt
            break

    # ── Error general: no se encontró ningún registro ─────────────────────────
    todos_vacios = (
        not result["a_records"]
        and not result["aaaa_records"]
        and not result["ns_records"]
    )
    if todos_vacios:
        result["error"] = (
            "No se encontraron registros DNS para este dominio. "
            "Comprueba que el dominio existe y es accesible."
        )

    return result


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS PRIVADOS
# ══════════════════════════════════════════════════════════════════════════════

def _query(name: str, record_type: str) -> list[str]:
    """
    Realiza una consulta DNS y devuelve los resultados como lista de strings.

    Si la consulta falla por cualquier motivo (dominio inexistente, timeout,
    tipo de registro no disponible...) devuelve una lista vacía en lugar de
    lanzar una excepción. Así la app nunca se rompe por un fallo DNS.

    Args:
        name:        Nombre a consultar (dominio o subdominio).
        record_type: Tipo de registro DNS ('A', 'MX', 'TXT', etc.).

    Returns:
        Lista de strings con los valores encontrados, o lista vacía.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT   # tiempo máximo total de la consulta

        answers = resolver.resolve(name, record_type)
        return [_format_record(r, record_type) for r in answers]

    except dns.resolver.NXDOMAIN:
        # El dominio o subdominio no existe
        return []

    except dns.resolver.NoAnswer:
        # El dominio existe pero no tiene ese tipo de registro
        return []

    except dns.resolver.Timeout:
        # El servidor DNS tardó demasiado en responder
        return []

    except dns.exception.DNSException:
        # Cualquier otro error de dnspython
        return []


def _format_record(record, record_type: str) -> str:
    """
    Convierte un objeto de registro DNS en un string legible.

    Cada tipo de registro tiene su propio formato:
      · MX incluye prioridad y servidor  →  "10 mail.ejemplo.com"
      · TXT une los fragmentos separados por espacios
      · El resto se convierte directamente a string

    Args:
        record:      Objeto de registro devuelto por dnspython.
        record_type: Tipo de registro ('A', 'MX', 'TXT', etc.).

    Returns:
        String con el valor del registro.
    """
    if record_type == "MX":
        # Los registros MX tienen prioridad y nombre de servidor
        return f"{record.preference} {record.exchange.to_text().rstrip('.')}"

    if record_type == "TXT":
        # Los registros TXT pueden estar fragmentados en varios strings
        return b" ".join(record.strings).decode("utf-8", errors="replace")

    # Para A, AAAA, NS y el resto, la conversión estándar funciona bien
    return record.to_text().rstrip(".")


def _empty_result(domain: str, error: str) -> dict:
    """Devuelve un resultado vacío con un mensaje de error."""
    return {
        "domain":       domain,
        "a_records":    [],
        "aaaa_records": [],
        "mx_records":   [],
        "ns_records":   [],
        "txt_records":  [],
        "spf_found":    False,
        "dmarc_found":  False,
        "dmarc_record": None,
        "error":        error,
    }
