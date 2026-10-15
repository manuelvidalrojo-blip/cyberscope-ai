"""
subdomains.py
-------------
Descubrimiento pasivo de subdominios a partir de Certificate Transparency
(crt.sh). Cada certificado TLS emitido públicamente queda registrado en logs
públicos; consultándolos se ven los nombres para los que se han emitido.

No se contacta con los subdominios: solo se listan.
"""

from __future__ import annotations

import requests

from modules.utils import validate_domain

CRTSH_URL = "https://crt.sh/"
TIMEOUT = 20
MAX_SUBDOMAINS = 200


def find_subdomains(domain: str) -> dict:
    """
    Busca subdominios de `domain` en los logs de Certificate Transparency.

    Returns:
        dict con subdomains (ordenados), total, truncated, source y error.
    """
    result = {
        "subdomains": [],
        "total":      0,
        "truncated":  False,
        "source":     "crt.sh (Certificate Transparency)",
        "error":      None,
    }
    try:
        response = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=TIMEOUT,
            headers={"User-Agent": "CyberScope-AI/2.0"},
        )
        response.raise_for_status()
        entries = response.json()
    except requests.exceptions.Timeout:
        result["error"] = "crt.sh no respondió a tiempo (servicio lento o saturado)."
        return result
    except (requests.exceptions.RequestException, ValueError):
        result["error"] = "No se pudo consultar crt.sh (servicio no disponible)."
        return result

    names = parse_crtsh(domain, entries)
    result["total"] = len(names)
    result["truncated"] = len(names) > MAX_SUBDOMAINS
    result["subdomains"] = names[:MAX_SUBDOMAINS]
    return result


def parse_crtsh(domain: str, entries) -> list[str]:
    """
    Extrae nombres únicos que pertenecen a `domain` del JSON de crt.sh.

    Se descartan comodines (*.), nombres de otros dominios y valores mal formados.
    """
    found: set[str] = set()
    if not isinstance(entries, list):
        return []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name != domain and name.endswith("." + domain) and validate_domain(name):
                found.add(name)
    return sorted(found)
