"""
scanner.py
----------
Módulo de escaneo de infraestructura externa.
 
Fase 2 — implementado:
    · scan_domain(): conectividad HTTP/HTTPS, redirecciones, estado
 
Pendiente:
    · Resolución DNS (A, MX, TXT, NS, CNAME)
    · Escaneo de puertos comunes
    · Detección de tecnologías expuestas
"""
 
import requests
 
# Tiempo máximo de espera por petición (segundos)
TIMEOUT = 10
 
 
def scan_domain(domain: str) -> dict:
    """
    Analiza la conectividad HTTP y HTTPS de un dominio.
 
    Realiza dos peticiones independientes (http:// y https://) y detecta
    si el dominio usa HTTPS y si redirige automáticamente desde HTTP.
 
    Args:
        domain: Dominio objetivo sin esquema (ej. 'ejemplo.com').
 
    Returns:
        Diccionario con el siguiente formato:
        {
            "domain":             str,        # dominio analizado
            "http_status":        int | None, # código de estado HTTP (80)
            "https_status":       int | None, # código de estado HTTPS (443)
            "uses_https":         bool,       # True si HTTPS responde con éxito
            "redirects_to_https": bool,       # True si HTTP redirige a HTTPS
            "error":              str | None  # mensaje de error general, si aplica
        }
    """
    # ── Validación básica ──────────────────────────────────────────────────────
    if not domain or not domain.strip():
        return _empty_result(domain, error="El dominio no puede estar vacío.")
 
    domain = domain.strip()
 
    # ── Resultado base ─────────────────────────────────────────────────────────
    result = {
        "domain":             domain,
        "http_status":        None,
        "https_status":       None,
        "uses_https":         False,
        "redirects_to_https": False,
        "error":              None,
    }
 
    # ── Petición HTTP ──────────────────────────────────────────────────────────
    http_response = _get(f"http://{domain}")
 
    if http_response is not None:
        result["http_status"] = http_response.status_code
 
        # Comprobar si la cadena de redirecciones acabó en HTTPS
        final_url = http_response.url
        if final_url.startswith("https://"):
            result["redirects_to_https"] = True
 
    # ── Petición HTTPS ─────────────────────────────────────────────────────────
    https_response = _get(f"https://{domain}")
 
    if https_response is not None:
        result["https_status"] = https_response.status_code
 
        # Consideramos que "usa HTTPS" si el servidor responde sin error grave
        if https_response.status_code < 500:
            result["uses_https"] = True
 
    # ── Error general: ninguna petición tuvo éxito ────────────────────────────
    if result["http_status"] is None and result["https_status"] is None:
        result["error"] = (
            "No se pudo conectar al dominio por HTTP ni HTTPS. "
            "Comprueba que el dominio existe y es accesible."
        )
 
    return result
 
 
# ── Helpers privados ───────────────────────────────────────────────────────────
 
def _get(url: str):
    """
    Realiza una petición GET tolerante a errores.
 
    Sigue redirecciones automáticamente (allow_redirects=True).
    Devuelve None si hay cualquier error de red o timeout.
 
    Args:
        url: URL completa con esquema.
 
    Returns:
        Objeto Response o None en caso de error.
    """
    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "CyberScope-AI/1.0"},
        )
        return response
 
    except requests.exceptions.SSLError:
        # Certificado inválido o caducado
        return None
 
    except requests.exceptions.ConnectionError:
        # Dominio inexistente o sin conectividad
        return None
 
    except requests.exceptions.Timeout:
        # El servidor tardó demasiado en responder
        return None
 
    except requests.exceptions.RequestException:
        # Cualquier otro error de requests
        return None
 
 
def _empty_result(domain: str, error: str) -> dict:
    """Devuelve un resultado vacío con un mensaje de error."""
    return {
        "domain":             domain,
        "http_status":        None,
        "https_status":       None,
        "uses_https":         False,
        "redirects_to_https": False,
        "error":              error,
    }
 
