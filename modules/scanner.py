"""
scanner.py
----------
Conectividad HTTP/HTTPS del dominio y detección pasiva de tecnologías.

Todo se obtiene de UNA petición GET normal a http:// y otra a https://,
igual que haría un navegador. No hay escaneo de puertos ni pruebas intrusivas.
"""

from __future__ import annotations

import re

from modules.http_client import FetchError, FetchResult, safe_get

# Cabeceras que suelen revelar el software del servidor
TECH_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via"]

# Pistas indirectas: cabecera o cookie → tecnología
TECH_HINTS = {
    "cf-ray":            "Cloudflare (CDN)",
    "x-amz-cf-id":       "Amazon CloudFront (CDN)",
    "x-vercel-id":       "Vercel",
    "x-served-by":       "Fastly (CDN)",
    "x-drupal-cache":    "Drupal",
    "x-shopify-stage":   "Shopify",
}
COOKIE_HINTS = {
    "phpsessid":         "PHP",
    "jsessionid":        "Java (servlet)",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session":   "Laravel (PHP)",
    "wordpress_":        "WordPress",
    "wp-settings":       "WordPress",
    "django":            "Django (Python)",
}

_VERSION_RE = re.compile(r"\d+\.\d+")


def scan_domain(domain: str, https_fetch: FetchResult | None = None) -> dict:
    """
    Analiza la conectividad HTTP y HTTPS de un dominio.

    Args:
        domain:      Dominio ya validado (ej. 'ejemplo.com').
        https_fetch: Respuesta HTTPS ya obtenida (evita repetir la petición).

    Returns:
        dict con http_status, https_status, uses_https, redirects_to_https,
        technologies, version_disclosure y error.
    """
    result = {
        "domain":             domain,
        "http_status":        None,
        "https_status":       None,
        "uses_https":         False,
        "redirects_to_https": False,
        "final_url":          None,
        "technologies":       [],
        "version_disclosure": [],
        "error":              None,
    }

    errors = []

    # ── HTTP (puerto 80) ───────────────────────────────────────────────────────
    try:
        http = safe_get(f"http://{domain}")
        result["http_status"] = http.status_code
        result["redirects_to_https"] = http.url.startswith("https://")
    except FetchError as exc:
        errors.append(f"HTTP: {exc}")

    # ── HTTPS (puerto 443) ─────────────────────────────────────────────────────
    if https_fetch is None:
        try:
            https_fetch = safe_get(f"https://{domain}")
        except FetchError as exc:
            errors.append(f"HTTPS: {exc}")

    if https_fetch is not None:
        result["https_status"] = https_fetch.status_code
        result["final_url"] = https_fetch.url
        result["uses_https"] = https_fetch.status_code < 500
        techs, disclosed = detect_technologies(https_fetch.headers)
        result["technologies"] = techs
        result["version_disclosure"] = disclosed

    if result["http_status"] is None and result["https_status"] is None:
        result["error"] = " · ".join(errors) or "No se pudo conectar por HTTP ni HTTPS."

    return result


def detect_technologies(headers) -> tuple[list[str], list[str]]:
    """
    Deduce tecnologías a partir de las cabeceras de respuesta.

    Returns:
        (tecnologías detectadas, cabeceras que revelan una versión concreta)
    """
    techs: list[str] = []
    disclosed: list[str] = []
    lower = {k.lower(): v for k, v in headers.items()}

    for name in TECH_HEADERS:
        value = lower.get(name.lower())
        if value:
            techs.append(f"{name}: {value[:80]}")
            if _VERSION_RE.search(value):
                disclosed.append(name)

    for header, tech in TECH_HINTS.items():
        if header in lower and tech not in techs:
            techs.append(tech)

    cookies = lower.get("set-cookie", "").lower()
    for marker, tech in COOKIE_HINTS.items():
        if marker in cookies and tech not in techs:
            techs.append(tech)

    return techs, disclosed
