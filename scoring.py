"""
scoring.py
----------
Módulo de puntuación global de seguridad.
 
Combina los resultados de scanner.py y headers.py para producir
un score único de 0 a 100 y un nivel de riesgo general.
"""
 
 
# ── Función principal ──────────────────────────────────────────────────────────
 
def calculate_global_score(scan_result: dict, headers_result: dict) -> dict:
    """
    Calcula una puntuación global de seguridad combinando los resultados
    del escaneo HTTP/HTTPS y del análisis de cabeceras.
 
    La puntuación se divide en dos mitades de igual peso:
      · 50 puntos máximo por conectividad y configuración HTTPS
      · 50 puntos máximo por cabeceras de seguridad
 
    Args:
        scan_result:    Salida de scanner.scan_domain().
        headers_result: Salida de headers.analyze_security_headers().
 
    Returns:
        Diccionario con score global, nivel de riesgo y resumen explicativo.
    """
 
    # ──────────────────────────────────────────────────────────────────────────
    # BLOQUE 1 — Puntuación por conectividad HTTPS (máximo 50 puntos)
    # ──────────────────────────────────────────────────────────────────────────
 
    # Empezamos con los 50 puntos completos y vamos restando
    https_score = 50
 
    # Si hubo un error grave al escanear (dominio inaccesible, etc.)
    # no podemos saber nada → penalización máxima
    if scan_result.get("error"):
        https_score -= 40
 
    else:
        # El dominio no responde en HTTPS → penalización grave
        if not scan_result.get("uses_https"):
            https_score -= 30
 
        # El dominio no redirige HTTP → HTTPS → penalización leve
        if not scan_result.get("redirects_to_https"):
            https_score -= 10
 
    # Nos aseguramos de que no baje de 0
    https_score = max(https_score, 0)
 
 
    # ──────────────────────────────────────────────────────────────────────────
    # BLOQUE 2 — Puntuación por cabeceras de seguridad (máximo 50 puntos)
    # ──────────────────────────────────────────────────────────────────────────
 
    # headers_result["security_score_headers"] va de 0 a 100.
    # Lo convertimos a una escala de 0 a 50 (la mitad del total).
    raw_headers_score = headers_result.get("security_score_headers", 0)
    headers_score = raw_headers_score / 2   # 100 → 50, 70 → 35, 0 → 0
 
 
    # ──────────────────────────────────────────────────────────────────────────
    # BLOQUE 3 — Score global y nivel de riesgo
    # ──────────────────────────────────────────────────────────────────────────
 
    # Sumamos las dos mitades y redondeamos a entero
    global_score = round(https_score + headers_score)
 
    # Por seguridad, limitamos el rango a [0, 100]
    global_score = max(0, min(100, global_score))
 
    risk_level = _get_risk_level(global_score)
 
 
    # ──────────────────────────────────────────────────────────────────────────
    # BLOQUE 4 — Resumen explicativo en lenguaje sencillo
    # ──────────────────────────────────────────────────────────────────────────
 
    summary = _build_summary(global_score, risk_level, scan_result, headers_result)
 
    return {
        "global_score": global_score,
        "risk_level":   risk_level,
        "summary":      summary,
    }
 
 
# ── Helpers privados ───────────────────────────────────────────────────────────
 
def _get_risk_level(score: int) -> str:
    """
    Traduce una puntuación numérica a un nivel de riesgo.
 
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
 
 
def _build_summary(score: int, risk_level: str, scan_result: dict, headers_result: dict) -> str:
    """
    Genera un resumen en lenguaje natural del estado de seguridad del dominio.
 
    Describe los puntos fuertes y débiles de forma sencilla,
    pensada para un usuario no técnico.
 
    Args:
        score:          Puntuación global calculada.
        risk_level:     Nivel de riesgo ('Bajo', 'Medio' o 'Alto').
        scan_result:    Resultado del escaneo HTTP/HTTPS.
        headers_result: Resultado del análisis de cabeceras.
 
    Returns:
        Cadena de texto con el resumen.
    """
    domain = scan_result.get("domain", "el dominio")
    num_missing = len(headers_result.get("missing_headers", []))
    num_total   = 6  # total de cabeceras que analizamos
 
    # Introducción según nivel de riesgo
    if risk_level == "Bajo":
        intro = (
            f"{domain} tiene una configuración de seguridad buena "
            f"(puntuación {score}/100)."
        )
    elif risk_level == "Medio":
        intro = (
            f"{domain} tiene una configuración de seguridad mejorable "
            f"(puntuación {score}/100)."
        )
    else:
        intro = (
            f"{domain} presenta riesgos de seguridad importantes "
            f"(puntuación {score}/100)."
        )
 
    # Estado de HTTPS
    if scan_result.get("error"):
        https_comment = "No se pudo verificar la conectividad del dominio."
    elif scan_result.get("uses_https") and scan_result.get("redirects_to_https"):
        https_comment = "HTTPS está activo y las visitas HTTP se redirigen automáticamente."
    elif scan_result.get("uses_https"):
        https_comment = "HTTPS está activo, pero el sitio no redirige desde HTTP."
    else:
        https_comment = "El sitio no usa HTTPS, lo que expone el tráfico sin cifrar."
 
    # Estado de las cabeceras
    num_present = num_total - num_missing
    if num_missing == 0:
        headers_comment = "Todas las cabeceras de seguridad están presentes."
    elif num_missing <= 2:
        headers_comment = (
            f"Tiene {num_present} de {num_total} cabeceras de seguridad. "
            f"Faltan {num_missing} cabecera(s) menores."
        )
    else:
        headers_comment = (
            f"Solo tiene {num_present} de {num_total} cabeceras de seguridad. "
            f"Faltan {num_missing} cabeceras importantes."
        )
 
    # Unimos todo en un párrafo legible
    return f"{intro} {https_comment} {headers_comment}"
 