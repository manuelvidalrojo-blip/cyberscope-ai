"""
analysis.py
-----------
Orquestador del análisis completo de un dominio.

1. Limpia y valida el dominio y comprueba que su IP es pública (anti-SSRF).
2. Lanza los módulos en paralelo (ThreadPoolExecutor): en la Práctica 1 iban
   en secuencia y el análisis tardaba la suma de todos.
3. Calcula la puntuación global y devuelve un único dict serializable a JSON.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from modules.dns_analyzer import analyze_dns
from modules.exposure import analyze_exposure
from modules.headers import SECURITY_HEADERS, analyze_security_headers
from modules.http_client import FetchError, safe_get
from modules.scanner import scan_domain
from modules.scoring import calculate_global_score
from modules.subdomains import find_subdomains
from modules.tls_analyzer import analyze_tls
from modules.utils import TargetNotAllowed, check_target, sanitize_domain

__all__ = ["run_analysis", "TargetNotAllowed"]


def run_analysis(raw_domain: str) -> dict:
    """
    Ejecuta el análisis completo.

    Raises:
        TargetNotAllowed: si el dominio no es válido o no se puede analizar.

    Returns:
        dict con domain, ips, timestamp, duration_s y los resultados de cada
        módulo (scan, headers, dns, tls, exposure, subdomains, score).
    """
    started = time.monotonic()
    domain = sanitize_domain(raw_domain)
    ips = check_target(domain)          # lanza TargetNotAllowed si no procede

    with ThreadPoolExecutor(max_workers=6) as pool:
        f_https = pool.submit(_fetch_https, domain)
        f_dns = pool.submit(analyze_dns, domain)
        f_tls = pool.submit(analyze_tls, domain)
        f_exposure = pool.submit(analyze_exposure, ips)
        f_subdomains = pool.submit(find_subdomains, domain)

        https_fetch, https_error = f_https.result()
        f_scan = pool.submit(scan_domain, domain, https_fetch)
        if https_fetch is not None:
            headers = analyze_security_headers(domain, https_fetch)
        else:
            headers = _headers_error(domain, https_error)

        scan = f_scan.result()
        dns = f_dns.result()
        tls = f_tls.result()
        exposure = f_exposure.result()
        subdomains = f_subdomains.result()

    score = calculate_global_score(scan, headers, dns, tls, exposure)

    return {
        "domain":     domain,
        "ips":        ips,
        "timestamp":  datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - started, 1),
        "scan":       scan,
        "headers":    headers,
        "dns":        dns,
        "tls":        tls,
        "exposure":   exposure,
        "subdomains": subdomains,
        "score":      score,
    }


def _fetch_https(domain: str):
    """Una sola petición HTTPS compartida por scanner y headers."""
    try:
        return safe_get(f"https://{domain}"), None
    except FetchError as exc:
        return None, str(exc)


def _headers_error(domain: str, error: str | None) -> dict:
    """Resultado de cabeceras cuando HTTPS no responde (todas ausentes)."""
    return {
        "domain":                 domain,
        "url":                    f"https://{domain}",
        "headers_found":          {h: None for h in SECURITY_HEADERS},
        "missing_headers":        list(SECURITY_HEADERS),
        "security_score_headers": 0,
        "risk_level_headers":     "Alto",
        "recommendations":        [],
        "error":                  error or "HTTPS no disponible.",
    }
