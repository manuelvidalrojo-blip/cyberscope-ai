"""
scoring.py
----------
Puntuación global de seguridad (0-100) y recomendaciones priorizadas.

Modelo v2 (Práctica 3). En la Práctica 1 solo puntuaban HTTPS (50) y
cabeceras (50): el DNS, SPF y DMARC se analizaban pero no contaban, y el
certificado no se revisaba. Ahora cada área tiene su peso:

    · HTTPS y redirección ........ 25 pts
    · Cabeceras de seguridad ..... 30 pts
    · Certificado TLS ............ 20 pts
    · Correo (SPF + DMARC) ....... 25 pts
    · Penalización por servicios peligrosos expuestos: hasta -15 pts

Niveles de riesgo (sin cambios): 80-100 Bajo · 50-79 Medio · 0-49 Alto.
"""

from __future__ import annotations

WEIGHTS = {"https": 25, "headers": 30, "tls": 20, "email": 25}
RISKY_PORT_PENALTY = 5
MAX_EXPOSURE_PENALTY = 15

SEVERITY_ORDER = {"Alta": 0, "Media": 1, "Baja": 2}


def calculate_global_score(
    scan_result: dict,
    headers_result: dict,
    dns_result: dict | None = None,
    tls_result: dict | None = None,
    exposure_result: dict | None = None,
) -> dict:
    """
    Calcula la puntuación global combinando todos los módulos.

    Los módulos opcionales que no se pasen (None) puntúan 0 en su bloque:
    lo que no se ha podido comprobar no se da por bueno.

    Returns:
        dict con global_score, risk_level, breakdown (puntos por área),
        recommendations (lista priorizada) y summary.
    """
    dns_result = dns_result or {}
    tls_result = tls_result or {}
    exposure_result = exposure_result or {}

    breakdown = {
        "https":   _score_https(scan_result),
        "headers": _score_headers(headers_result),
        "tls":     _score_tls(tls_result),
        "email":   _score_email(dns_result),
        "exposure_penalty": -min(
            MAX_EXPOSURE_PENALTY,
            RISKY_PORT_PENALTY * len(exposure_result.get("risky_ports", [])),
        ),
    }

    global_score = max(0, min(100, round(sum(breakdown.values()))))
    risk_level = _get_risk_level(global_score)
    recommendations = build_recommendations(
        scan_result, headers_result, dns_result, tls_result, exposure_result
    )

    return {
        "global_score":    global_score,
        "risk_level":      risk_level,
        "breakdown":       breakdown,
        "max_points":      dict(WEIGHTS),
        "recommendations": recommendations,
        "summary":         _build_summary(global_score, risk_level, scan_result, headers_result, dns_result, tls_result),
    }


# ── Puntuación por bloques ─────────────────────────────────────────────────────

def _score_https(scan: dict) -> float:
    if scan.get("error") or not scan.get("uses_https"):
        return 0
    score = 15                                    # HTTPS responde
    if scan.get("redirects_to_https"):
        score += 10                               # HTTP → HTTPS automático
    return score


def _score_headers(headers: dict) -> float:
    # security_score_headers va de 0 a 100 → lo llevamos a 0-30
    return headers.get("security_score_headers", 0) * WEIGHTS["headers"] / 100


def _score_tls(tls: dict) -> float:
    if not tls.get("trusted"):
        return 0
    score = 10                                    # certificado válido y confiable
    if tls.get("secure_version"):
        score += 5                                # TLS 1.2 o 1.3
    if not tls.get("expiring_soon"):
        score += 5                                # no caduca en < 30 días
    return score


def _score_email(dns: dict) -> float:
    score = 0
    if dns.get("spf_found"):
        score += 12 if dns.get("spf_all") in ("-all", "~all") else 6
    if dns.get("dmarc_found"):
        score += {"reject": 13, "quarantine": 11}.get(dns.get("dmarc_policy"), 5)
    return score


def _get_risk_level(score: int) -> str:
    """Traduce una puntuación de 0 a 100 a 'Bajo', 'Medio' o 'Alto'."""
    if score >= 80:
        return "Bajo"
    elif score >= 50:
        return "Medio"
    else:
        return "Alto"


# ── Recomendaciones ────────────────────────────────────────────────────────────

def build_recommendations(scan, headers, dns, tls, exposure) -> list[dict]:
    """Une las recomendaciones de todas las áreas, ordenadas por severidad."""
    recs: list[dict] = []

    def add(severity, area, text):
        recs.append({"severity": severity, "area": area, "text": text})

    # HTTPS
    if not scan.get("error"):
        if not scan.get("uses_https"):
            add("Alta", "HTTPS", "El sitio no responde por HTTPS: todo el tráfico viaja sin cifrar. Instala un certificado (p. ej. Let's Encrypt).")
        elif not scan.get("redirects_to_https"):
            add("Media", "HTTPS", "HTTP no redirige a HTTPS. Añade una redirección 301 de http:// a https://.")
    for header in scan.get("version_disclosure", []):
        add("Baja", "Tecnologías", f"La cabecera '{header}' revela la versión del software. Ocúltala para no facilitar la búsqueda de vulnerabilidades.")

    # Cabeceras
    if not headers.get("error"):
        for text in headers.get("recommendations", []):
            severity = "Media" if any(h in text for h in ("Strict-Transport-Security", "Content-Security-Policy")) else "Baja"
            add(severity, "Cabeceras", text)

    # TLS
    if tls:
        if tls.get("error"):
            add("Alta", "TLS", f"{tls['error']} Revisa la instalación del certificado.")
        else:
            if tls.get("expiring_soon"):
                add("Alta", "TLS", f"El certificado caduca en {tls.get('days_left')} días. Renuévalo o automatiza la renovación.")
            if not tls.get("secure_version"):
                add("Media", "TLS", f"Se negoció {tls.get('tls_version')}. Desactiva TLS 1.0/1.1 y usa TLS 1.2 o superior.")

    # Correo
    if dns and not dns.get("error"):
        if not dns.get("spf_found"):
            add("Alta", "Correo", "No hay registro SPF: cualquiera puede enviar correo suplantando el dominio. Publica un TXT 'v=spf1 ... -all'.")
        elif dns.get("spf_all") == "+all":
            add("Alta", "Correo", "El SPF termina en '+all', que autoriza a cualquier servidor. Cámbialo a '-all' o '~all'.")
        elif dns.get("spf_all") in (None, "?all"):
            add("Media", "Correo", "El SPF no tiene un final restrictivo. Termina el registro con '-all' o '~all'.")
        if not dns.get("dmarc_found"):
            add("Alta", "Correo", "No hay política DMARC. Publica '_dmarc' con 'v=DMARC1; p=quarantine; rua=mailto:...'.")
        elif dns.get("dmarc_policy") in (None, "none"):
            add("Media", "Correo", "DMARC está en modo 'p=none' (solo monitoriza). Pasa a 'quarantine' o 'reject' cuando revises los informes.")

    # Exposición (InternetDB)
    for item in exposure.get("risky_ports", []):
        add("Alta", "Exposición", f"Puerto {item['port']} ({item['service']}) visible desde Internet. Ciérralo o restríngelo por cortafuegos/VPN.")
    if exposure.get("vulns"):
        add("Alta", "Exposición", f"Shodan asocia {len(exposure['vulns'])} CVE a las IPs del dominio. Revisa y actualiza el software expuesto.")

    recs.sort(key=lambda r: SEVERITY_ORDER[r["severity"]])
    return recs


# ── Resumen en lenguaje sencillo ───────────────────────────────────────────────

def _build_summary(score, risk_level, scan, headers, dns, tls) -> str:
    domain = scan.get("domain", "el dominio")
    intro = {
        "Bajo":  f"{domain} tiene una configuración de seguridad buena (puntuación {score}/100).",
        "Medio": f"{domain} tiene una configuración de seguridad mejorable (puntuación {score}/100).",
        "Alto":  f"{domain} presenta riesgos de seguridad importantes (puntuación {score}/100).",
    }[risk_level]

    if scan.get("error"):
        https = "No se pudo verificar la conectividad del dominio."
    elif scan.get("uses_https") and scan.get("redirects_to_https"):
        https = "HTTPS está activo y las visitas HTTP se redirigen automáticamente."
    elif scan.get("uses_https"):
        https = "HTTPS está activo, pero el sitio no redirige desde HTTP."
    else:
        https = "El sitio no usa HTTPS, lo que expone el tráfico sin cifrar."

    missing = len(headers.get("missing_headers", []))
    cabeceras = (
        "Todas las cabeceras de seguridad están presentes."
        if missing == 0 else f"Faltan {missing} de 6 cabeceras de seguridad."
    )

    if tls.get("trusted"):
        certificado = f"El certificado es válido y caduca en {tls.get('days_left')} días."
    elif tls:
        certificado = "El certificado TLS presenta problemas."
    else:
        certificado = ""

    correo = ""
    if dns:
        estados = [
            "SPF" + ("" if dns.get("spf_found") else " ausente"),
            "DMARC" + (f" ({dns.get('dmarc_policy')})" if dns.get("dmarc_found") else " ausente"),
        ]
        correo = "Correo: " + ", ".join(estados) + "."

    return " ".join(p for p in (intro, https, cabeceras, certificado, correo) if p)
