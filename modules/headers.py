
"""
headers.py
----------
Módulo de análisis de cabeceras de seguridad HTTP.
 
Comprueba si un dominio incluye las cabeceras de seguridad más importantes
y genera una puntuación de riesgo basada en cuántas están presentes.
"""
 
import requests
 
# ── Constantes ─────────────────────────────────────────────────────────────────
 
TIMEOUT = 10
 
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
 
def analyze_security_headers(domain: str) -> dict:
    """
    Analiza las cabeceras de seguridad HTTP de un dominio via HTTPS.
 
    Args:
        domain: Dominio objetivo sin esquema (ej. 'ejemplo.com').
 
    Returns:
        Diccionario con cabeceras encontradas, ausentes, puntuación,
        nivel de riesgo, recomendaciones y posibles errores.
    """
    url = f"https://{domain}"
 
    # ── Resultado base (se rellena a lo largo de la función) ───────────────────
    result = {
        "domain":               domain,
        "url":                  url,
        "headers_found":        {h: None for h in SECURITY_HEADERS},
        "missing_headers":      [],
        "security_score_headers": 0,
        "risk_level_headers":   "Alto",
        "recommendations":      [],
        "error":                None,
    }
 
    # ── Petición HTTPS ─────────────────────────────────────────────────────────
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScope-AI/1.0"},
        )
    except requests.exceptions.SSLError:
        result["error"] = "Error SSL: el certificado del dominio no es válido o ha caducado."
        return result
    except requests.exceptions.ConnectionError:
        result["error"] = "No se pudo conectar al dominio. Comprueba que existe y es accesible."
        return result
    except requests.exceptions.Timeout:
        result["error"] = f"Tiempo de espera agotado tras {TIMEOUT} segundos."
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"Error inesperado al conectar: {e}"
        return result
 
    # ── Comprobar cada cabecera de seguridad ───────────────────────────────────
    for header in SECURITY_HEADERS:
        # requests devuelve las cabeceras sin distinguir mayúsculas/minúsculas
        valor = response.headers.get(header)
 
        if valor:
            # La cabecera está presente → guardamos su valor
            result["headers_found"][header] = valor
        else:
            # La cabecera no está presente → la añadimos a ausentes y recomendamos
            result["missing_headers"].append(header)
            result["recommendations"].append(RECOMMENDATIONS[header])
 
    # ── Calcular puntuación ────────────────────────────────────────────────────
    num_presentes = len(SECURITY_HEADERS) - len(result["missing_headers"])
    result["security_score_headers"] = SCORE_TABLE[num_presentes]
 
    # ── Calcular nivel de riesgo ───────────────────────────────────────────────
    result["risk_level_headers"] = _get_risk_level(result["security_score_headers"])
 
    return result
 
 
# ── Helper privado ─────────────────────────────────────────────────────────────
 
def _get_risk_level(score: int) -> str:
    """
    Traduce una puntuación numérica a un nivel de riesgo legible.
 
    Args:
        score: Puntuación de 0 a 100.
 
    Returns:
        'Bajo', 'Medio' o 'Alto'.
    """
    if score >= 80:
        return "Bajo"
    elif score >= 50:
        return "Medio"
    else:
        return "Alto"