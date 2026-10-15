"""
headers.py
----------
Módulo de análisis de cabeceras de seguridad HTTP.

Comprueba si un dominio incluye las cabeceras de seguridad más importantes
y genera una puntuación de riesgo basada en cuántas están presentes.
"""

from __future__ import annotations

from modules.http_client import FetchError, FetchResult, safe_get

# Cabeceras de seguridad que vamos a comprobar
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Tabla de puntuación según número de cabeceras presentes
SCORE_TABLE = {
    6: 100,
    5: 85,
    4: 70,
    3: 50,
    2: 35,
    1: 20,
    0: 0,
}

# Recomendaciones para cada cabecera ausente
RECOMMENDATIONS = {
    "Strict-Transport-Security": (
        "Añade 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "para forzar conexiones HTTPS."
    ),
    "Content-Security-Policy": (
        "Define una política 'Content-Security-Policy' para prevenir ataques XSS "
        "y carga de recursos no autorizados."
    ),
    "X-Frame-Options": (
        "Añade 'X-Frame-Options: DENY' o 'SAMEORIGIN' para evitar ataques de clickjacking."
    ),
    "X-Content-Type-Options": (
        "Añade 'X-Content-Type-Options: nosniff' para evitar que el navegador "
        "adivine el tipo de contenido."
    ),
    "Referrer-Policy": (
        "Define 'Referrer-Policy: no-referrer' o 'strict-origin-when-cross-origin' "
        "para controlar qué información se comparte al navegar."
    ),
    "Permissions-Policy": (
        "Usa 'Permissions-Policy' para restringir el acceso a APIs del navegador "
        "como cámara, micrófono o geolocalización."
    ),
}


# ── Función principal ──────────────────────────────────────────────────────────

def analyze_security_headers(domain: str, fetch: FetchResult | None = None) -> dict:
    """
    Analiza las cabeceras de seguridad HTTP de un dominio via HTTPS.

    Args:
        domain: Dominio objetivo sin esquema (ej. 'ejemplo.com').
        fetch:  Respuesta HTTPS ya obtenida (evita repetir la petición).

    Returns:
        Diccionario con cabeceras encontradas, ausentes, puntuación,
        nivel de riesgo, recomendaciones y posibles errores.
    """
    url = f"https://{domain}"

    result = {
        "domain":                 domain,
        "url":                    url,
        "headers_found":          {h: None for h in SECURITY_HEADERS},
        "missing_headers":        [],
        "security_score_headers": 0,
        "risk_level_headers":     "Alto",
        "recommendations":        [],
        "error":                  None,
    }

    if fetch is None:
        try:
            fetch = safe_get(url)
        except FetchError as exc:
            result["error"] = str(exc)
            result["missing_headers"] = list(SECURITY_HEADERS)
            return result

    # requests devuelve las cabeceras sin distinguir mayúsculas/minúsculas
    for header in SECURITY_HEADERS:
        valor = fetch.headers.get(header)
        if valor:
            result["headers_found"][header] = valor
        else:
            result["missing_headers"].append(header)
            result["recommendations"].append(RECOMMENDATIONS[header])

    num_presentes = len(SECURITY_HEADERS) - len(result["missing_headers"])
    result["security_score_headers"] = SCORE_TABLE[num_presentes]
    result["risk_level_headers"] = _get_risk_level(result["security_score_headers"])

    return result


def _get_risk_level(score: int) -> str:
    """Traduce una puntuación de 0 a 100 a 'Bajo', 'Medio' o 'Alto'."""
    if score >= 80:
        return "Bajo"
    elif score >= 50:
        return "Medio"
    else:
        return "Alto"
