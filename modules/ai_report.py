"""
report.py
---------
Módulo de generación de informes HTML.
 
Toma los resultados de los cuatro módulos de análisis y devuelve
un string con un informe HTML completo listo para guardar o descargar.
"""
 
from datetime import datetime
 
 
# ── Paleta de colores del tema oscuro ─────────────────────────────────────────
COLOR = {
    "bg":           "#0A0F1E",   # fondo principal
    "card":         "#0D1B2A",   # fondo de tarjetas
    "border":       "#1E3A5F",   # bordes sutiles
    "text":         "#C8D6E5",   # texto normal
    "muted":        "#8892A4",   # texto secundario
    "green":        "#00FFB2",   # riesgo bajo / presente
    "yellow":       "#FFC800",   # riesgo medio
    "red":          "#FF4B4B",   # riesgo alto / ausente
    "green_bg":     "rgba(0,255,178,0.08)",
    "yellow_bg":    "rgba(255,200,0,0.08)",
    "red_bg":       "rgba(255,75,75,0.08)",
}
 
 
# ══════════════════════════════════════════════════════════════════════════════
# FUNCIÓN PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════
 
def generate_html_report(
    domain:         str,
    scan_result:    dict,
    headers_result: dict,
    score_result:   dict,
    dns_result:     dict,
) -> str:
    """
    Genera un informe de auditoría completo en formato HTML.
 
    No escribe ningún archivo: devuelve el HTML como string para que
    el código que llama a esta función decida qué hacer con él
    (mostrar en pantalla, guardar en disco, ofrecer como descarga, etc.).
 
    Args:
        domain:         Dominio analizado (ej. 'ejemplo.com').
        scan_result:    Salida de scanner.scan_domain().
        headers_result: Salida de headers.analyze_security_headers().
        score_result:   Salida de scoring.calculate_global_score().
        dns_result:     Salida de dns_analyzer.analyze_dns().
 
    Returns:
        String con el documento HTML completo.
    """
 
    # Extraemos los valores que vamos a usar varias veces
    score     = score_result.get("global_score", 0)
    risk      = score_result.get("risk_level", "Alto")
    summary   = score_result.get("summary", "")
    timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
 
    # Colores dinámicos según nivel de riesgo
    risk_color, risk_bg = _risk_colors(risk)
 
    # Construimos cada sección por separado para mantener el código legible
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberScope AI Report — {domain}</title>
    {_styles()}
</head>
<body>
 
    {_header(domain, timestamp)}
    {_score_card(score, risk, risk_color, risk_bg, summary)}
    {_connectivity_section(scan_result)}
    {_headers_table(headers_result)}
    {_dns_section(dns_result)}
    {_recommendations_section(headers_result)}
    {_footer(timestamp)}
 
</body>
</html>"""
 
    return html
 
 
# ══════════════════════════════════════════════════════════════════════════════
# SECCIONES DEL INFORME
# ══════════════════════════════════════════════════════════════════════════════
 
def _header(domain: str, timestamp: str) -> str:
    """Cabecera del informe: logo, título y metadatos."""
    return f"""
    <header style="
        background: {COLOR['card']};
        border-bottom: 2px solid {COLOR['green']};
        padding: 2rem 3rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    ">
        <div>
            <div style="
                font-size: 0.65rem;
                letter-spacing: 3px;
                color: {COLOR['green']};
                font-family: monospace;
                margin-bottom: 0.4rem;
            ">◈ INFORME DE SEGURIDAD</div>
            <h1 style="
                margin: 0;
                font-size: 1.8rem;
                color: {COLOR['green']};
                font-family: monospace;
                letter-spacing: -0.5px;
            ">🛡️ CyberScope AI</h1>
        </div>
        <div style="text-align: right;">
            <div style="color: {COLOR['muted']}; font-size: 0.75rem;">Dominio analizado</div>
            <div style="
                color: {COLOR['text']};
                font-family: monospace;
                font-size: 1rem;
                font-weight: bold;
                margin-top: 0.2rem;
            ">{domain}</div>
            <div style="color: {COLOR['muted']}; font-size: 0.7rem; margin-top: 0.4rem;">
                {timestamp}
            </div>
        </div>
    </header>
    """
 
 
def _score_card(score: int, risk: str, risk_color: str, risk_bg: str, summary: str) -> str:
    """Tarjeta principal con score global, nivel de riesgo y resumen."""
    return f"""
    <section style="padding: 2rem 3rem 1rem;">
        <div style="
            background: {COLOR['card']};
            border: 1px solid {COLOR['border']};
            border-left: 4px solid {risk_color};
            border-radius: 6px;
            padding: 2rem;
            display: flex;
            align-items: center;
            gap: 2.5rem;
        ">
            <!-- Número grande del score -->
            <div style="text-align: center; min-width: 120px;">
                <div style="
                    font-family: monospace;
                    font-size: 4rem;
                    font-weight: bold;
                    color: {risk_color};
                    line-height: 1;
                ">{score}</div>
                <div style="
                    color: {COLOR['muted']};
                    font-size: 0.65rem;
                    letter-spacing: 2px;
                    margin-top: 0.3rem;
                ">/ 100</div>
            </div>
 
            <!-- Badge de riesgo y resumen -->
            <div style="flex: 1;">
                <span style="
                    background: {risk_bg};
                    color: {risk_color};
                    border: 1px solid {risk_color};
                    font-family: monospace;
                    font-size: 0.75rem;
                    font-weight: bold;
                    letter-spacing: 2px;
                    padding: 3px 14px;
                    border-radius: 2px;
                ">RIESGO {risk.upper()}</span>
 
                <p style="
                    color: {COLOR['text']};
                    font-size: 0.9rem;
                    line-height: 1.7;
                    margin: 0.8rem 0 0;
                ">{summary}</p>
            </div>
        </div>
    </section>
    """
 
 
def _connectivity_section(scan_result: dict) -> str:
    """Tabla de estado de conectividad HTTP / HTTPS."""
 
    http_status  = scan_result.get("http_status")
    https_status = scan_result.get("https_status")
    uses_https   = scan_result.get("uses_https", False)
    redirects    = scan_result.get("redirects_to_https", False)
    error        = scan_result.get("error")
 
    # Si hubo error mostramos un aviso en lugar de la tabla
    if error:
        return f"""
        <section style="padding: 0.5rem 3rem 1rem;">
            {_section_title("Conectividad")}
            <div style="
                background: {COLOR['red_bg']};
                border: 1px solid {COLOR['red']};
                border-radius: 4px;
                padding: 1rem 1.2rem;
                color: {COLOR['red']};
                font-size: 0.85rem;
            ">⚠ {error}</div>
        </section>
        """
 
    def _status_pill(value):
        """Devuelve un span con el código de estado coloreado."""
        if value is None:
            return _pill("N/A", COLOR['muted'], "transparent")
        color = COLOR['green'] if value < 400 else COLOR['red']
        return _pill(str(value), color, "transparent")
 
    def _bool_pill(value):
        text  = "Sí" if value else "No"
        color = COLOR['green'] if value else COLOR['red']
        return _pill(text, color, "transparent")
 
    rows = [
        ("HTTP Status",           _status_pill(http_status)),
        ("HTTPS Status",          _status_pill(https_status)),
        ("HTTPS activo",          _bool_pill(uses_https)),
        ("Redirige HTTP → HTTPS", _bool_pill(redirects)),
    ]
 
    filas_html = "".join([
        f"""
        <tr>
            <td style="
                padding: 0.7rem 1rem;
                color: {COLOR['muted']};
                font-size: 0.82rem;
                border-bottom: 1px solid {COLOR['border']};
                font-family: monospace;
            ">{nombre}</td>
            <td style="
                padding: 0.7rem 1rem;
                border-bottom: 1px solid {COLOR['border']};
            ">{valor_html}</td>
        </tr>
        """
        for nombre, valor_html in rows
    ])
 
    return f"""
    <section style="padding: 0.5rem 3rem 1rem;">
        {_section_title("Conectividad HTTP / HTTPS")}
        <table style="
            width: 100%;
            border-collapse: collapse;
            background: {COLOR['card']};
            border: 1px solid {COLOR['border']};
            border-radius: 6px;
            overflow: hidden;
        ">
            {filas_html}
        </table>
    </section>
    """
 
 
def _headers_table(headers_result: dict) -> str:
    """Tabla de cabeceras de seguridad: nombre, estado y valor."""
 
    headers_found = headers_result.get("headers_found", {})
 
    filas_html = ""
    for cabecera, valor in headers_found.items():
        presente = valor is not None
 
        estado_html = (
            _pill("Presente", COLOR['green'], COLOR['green_bg'])
            if presente else
            _pill("Ausente",  COLOR['red'],   COLOR['red_bg'])
        )
 
        # Truncamos valores muy largos para que no rompan el layout
        valor_texto = valor if valor and len(valor) <= 90 else (valor[:87] + "…" if valor else "—")
 
        filas_html += f"""
        <tr>
            <td style="
                padding: 0.7rem 1rem;
                font-family: monospace;
                font-size: 0.8rem;
                color: {COLOR['text']};
                border-bottom: 1px solid {COLOR['border']};
                white-space: nowrap;
            ">{cabecera}</td>
            <td style="
                padding: 0.7rem 1rem;
                border-bottom: 1px solid {COLOR['border']};
                text-align: center;
            ">{estado_html}</td>
            <td style="
                padding: 0.7rem 1rem;
                font-size: 0.75rem;
                color: {COLOR['muted']};
                border-bottom: 1px solid {COLOR['border']};
                word-break: break-all;
            ">{valor_texto}</td>
        </tr>
        """
 
    return f"""
    <section style="padding: 0.5rem 3rem 1rem;">
        {_section_title("Cabeceras de seguridad")}
        <table style="
            width: 100%;
            border-collapse: collapse;
            background: {COLOR['card']};
            border: 1px solid {COLOR['border']};
            border-radius: 6px;
            overflow: hidden;
        ">
            <!-- Encabezado de la tabla -->
            <thead>
                <tr style="border-bottom: 2px solid {COLOR['border']};">
                    <th style="padding:0.6rem 1rem; text-align:left; color:{COLOR['muted']};
                               font-size:0.65rem; letter-spacing:2px; font-weight:normal;">CABECERA</th>
                    <th style="padding:0.6rem 1rem; text-align:center; color:{COLOR['muted']};
                               font-size:0.65rem; letter-spacing:2px; font-weight:normal;">ESTADO</th>
                    <th style="padding:0.6rem 1rem; text-align:left; color:{COLOR['muted']};
                               font-size:0.65rem; letter-spacing:2px; font-weight:normal;">VALOR</th>
                </tr>
            </thead>
            <tbody>
                {filas_html}
            </tbody>
        </table>
    </section>
    """
 
 
def _dns_section(dns_result: dict) -> str:
    """Sección de análisis DNS: registros, SPF y DMARC."""
 
    error = dns_result.get("error")
 
    # Si hubo error mostramos un aviso en lugar del contenido
    if error:
        return f"""
        <section style="padding: 0.5rem 3rem 1rem;">
            {_section_title("DNS y correo")}
            <div style="
                background: {COLOR['red_bg']};
                border: 1px solid {COLOR['red']};
                border-radius: 4px;
                padding: 1rem 1.2rem;
                color: {COLOR['red']};
                font-size: 0.85rem;
            ">⚠ {error}</div>
        </section>
        """
 
    spf_found    = dns_result.get("spf_found",    False)
    dmarc_found  = dns_result.get("dmarc_found",  False)
    dmarc_record = dns_result.get("dmarc_record", None)
 
    # ── Tabla de estado SPF / DMARC ───────────────────────────────────────────
    spf_pill   = _pill("Sí", COLOR['green'], COLOR['green_bg']) if spf_found   else _pill("No", COLOR['red'], COLOR['red_bg'])
    dmarc_pill = _pill("Sí", COLOR['green'], COLOR['green_bg']) if dmarc_found else _pill("No", COLOR['red'], COLOR['red_bg'])
 
    estado_tabla = f"""
    <table style="
        width: 100%;
        border-collapse: collapse;
        background: {COLOR['card']};
        border: 1px solid {COLOR['border']};
        border-radius: 6px;
        overflow: hidden;
        margin-bottom: 1rem;
    ">
        <tr>
            <td style="padding:0.7rem 1rem; color:{COLOR['muted']}; font-family:monospace;
                       font-size:0.82rem; border-bottom:1px solid {COLOR['border']};">SPF detectado</td>
            <td style="padding:0.7rem 1rem; border-bottom:1px solid {COLOR['border']};">{spf_pill}</td>
        </tr>
        <tr>
            <td style="padding:0.7rem 1rem; color:{COLOR['muted']}; font-family:monospace;
                       font-size:0.82rem;">DMARC detectado</td>
            <td style="padding:0.7rem 1rem;">{dmarc_pill}</td>
        </tr>
    </table>
    """
 
    # ── Grupos de registros DNS ────────────────────────────────────────────────
    grupos = [
        ("Registros A",    "a_records"),
        ("Registros AAAA", "aaaa_records"),
        ("Registros MX",   "mx_records"),
        ("Registros NS",   "ns_records"),
    ]
 
    registros_html = ""
    for titulo, clave in grupos:
        valores = dns_result.get(clave, [])
        registros_html += _dns_record_block(titulo, valores)
 
    # ── Registro DMARC completo (si existe) ───────────────────────────────────
    dmarc_block = ""
    if dmarc_record:
        dmarc_block = f"""
        <div style="margin-bottom: 0.8rem;">
            <div style="
                color: {COLOR['muted']};
                font-size: 0.7rem;
                letter-spacing: 1px;
                margin-bottom: 0.3rem;
                font-family: monospace;
            ">REGISTRO DMARC</div>
            <div style="
                background: {COLOR['card']};
                border: 1px solid {COLOR['border']};
                border-left: 3px solid {COLOR['green']};
                border-radius: 0 4px 4px 0;
                padding: 0.6rem 1rem;
                font-family: monospace;
                font-size: 0.78rem;
                color: {COLOR['green']};
                word-break: break-all;
            ">{dmarc_record}</div>
        </div>
        """
 
    # ── Avisos si faltan SPF o DMARC ──────────────────────────────────────────
    avisos_html = ""
    if not spf_found:
        avisos_html += f"""
        <div style="
            margin-bottom: 0.6rem;
            padding: 0.8rem 1rem;
            background: {COLOR['yellow_bg']};
            border-left: 3px solid {COLOR['yellow']};
            border-radius: 0 4px 4px 0;
            color: {COLOR['text']};
            font-size: 0.84rem;
            line-height: 1.6;
        ">⚠ No se detectó registro SPF. Sin SPF, otros servidores pueden enviar correo
        suplantando tu dominio. Añade un registro TXT con tu política SPF.</div>
        """
    if not dmarc_found:
        avisos_html += f"""
        <div style="
            margin-bottom: 0.6rem;
            padding: 0.8rem 1rem;
            background: {COLOR['yellow_bg']};
            border-left: 3px solid {COLOR['yellow']};
            border-radius: 0 4px 4px 0;
            color: {COLOR['text']};
            font-size: 0.84rem;
            line-height: 1.6;
        ">⚠ No se detectó registro DMARC. Sin DMARC no puedes controlar qué ocurre
        con los correos que no superan la validación SPF o DKIM.</div>
        """
 
    return f"""
    <section style="padding: 0.5rem 3rem 1rem;">
        {_section_title("DNS y correo")}
        {estado_tabla}
        {registros_html}
        {dmarc_block}
        {avisos_html}
    </section>
    """
 
 
def _dns_record_block(titulo: str, valores: list) -> str:
    """
    Renderiza un bloque compacto con el título del tipo de registro
    y sus valores en píldoras, o un guión si no hay ninguno.
 
    Args:
        titulo:  Nombre del tipo de registro (ej. 'Registros A').
        valores: Lista de strings con los valores del registro.
 
    Returns:
        HTML del bloque.
    """
    if valores:
        # Cada valor va en su propia píldora
        pills_html = " ".join([
            f'<span style="'
            f'display:inline-block; margin:2px 4px 2px 0;'
            f'background:{COLOR["card"]}; color:{COLOR["text"]}; '
            f'border:1px solid {COLOR["border"]}; '
            f'font-family:monospace; font-size:0.75rem; '
            f'padding:2px 10px; border-radius:4px; word-break:break-all;'
            f'">{v}</span>'
            for v in valores
        ])
    else:
        pills_html = f'<span style="color:{COLOR["muted"]}; font-size:0.8rem;">—</span>'
 
    return f"""
    <div style="margin-bottom: 0.8rem;">
        <div style="
            color: {COLOR['muted']};
            font-size: 0.7rem;
            letter-spacing: 1px;
            margin-bottom: 0.4rem;
            font-family: monospace;
        ">{titulo.upper()}</div>
        <div>{pills_html}</div>
    </div>
    """
 
 
def _recommendations_section(headers_result: dict) -> str:
    """Lista de recomendaciones de seguridad."""
 
    recommendations = headers_result.get("recommendations", [])
 
    if not recommendations:
        return f"""
        <section style="padding: 0.5rem 3rem 1rem;">
            {_section_title("Recomendaciones")}
            <div style="
                background: {COLOR['green_bg']};
                border: 1px solid {COLOR['green']};
                border-radius: 4px;
                padding: 1rem 1.2rem;
                color: {COLOR['green']};
                font-size: 0.85rem;
            ">✅ Sin recomendaciones pendientes. Configuración excelente.</div>
        </section>
        """
 
    items_html = "".join([
        f"""
        <li style="
            margin-bottom: 0.7rem;
            padding: 0.8rem 1rem;
            background: {COLOR['yellow_bg']};
            border-left: 3px solid {COLOR['yellow']};
            border-radius: 0 4px 4px 0;
            color: {COLOR['text']};
            font-size: 0.84rem;
            line-height: 1.6;
        ">⚠ {rec}</li>
        """
        for rec in recommendations
    ])
 
    return f"""
    <section style="padding: 0.5rem 3rem 1rem;">
        {_section_title("Recomendaciones")}
        <ul style="list-style: none; padding: 0; margin: 0;">
            {items_html}
        </ul>
    </section>
    """
 
 
def _footer(timestamp: str) -> str:
    """Pie del informe con aviso legal y fecha."""
    return f"""
    <footer style="
        margin-top: 2rem;
        padding: 1.5rem 3rem;
        border-top: 1px solid {COLOR['border']};
        display: flex;
        justify-content: space-between;
        align-items: center;
    ">
        <div style="color: {COLOR['muted']}; font-size: 0.72rem; font-family: monospace;">
            CyberScope AI · Solo para uso ético y autorizado
        </div>
        <div style="color: {COLOR['muted']}; font-size: 0.72rem;">
            Generado el {timestamp}
        </div>
    </footer>
    """
 
 
# ══════════════════════════════════════════════════════════════════════════════
# HELPERS INTERNOS
# ══════════════════════════════════════════════════════════════════════════════
 
def _styles() -> str:
    """Estilos globales del documento (reset básico y tipografía)."""
    return f"""
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: {COLOR['bg']};
            color: {COLOR['text']};
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 15px;
            line-height: 1.5;
        }}
        table {{ border-spacing: 0; }}
    </style>
    """
 
 
def _section_title(title: str) -> str:
    """Título de sección con estilo monospace y letra espaciada."""
    return f"""
    <div style="
        font-family: monospace;
        font-size: 0.65rem;
        letter-spacing: 3px;
        color: {COLOR['muted']};
        text-transform: uppercase;
        margin: 0 0 0.8rem 0;
        padding-top: 0.5rem;
    ">◈ {title}</div>
    """
 
 
def _pill(text: str, color: str, bg: str) -> str:
    """Devuelve un span con forma de píldora para estados y badges."""
    return (
        f'<span style="'
        f'background:{bg}; color:{color}; border:1px solid {color}; '
        f'font-family:monospace; font-size:0.7rem; font-weight:bold; '
        f'letter-spacing:1px; padding:2px 10px; border-radius:20px; '
        f'white-space:nowrap;">{text}</span>'
    )
 
 
def _risk_colors(risk: str) -> tuple[str, str]:
    """
    Devuelve (color_texto, color_fondo) según el nivel de riesgo.
 
    Args:
        risk: 'Bajo', 'Medio' o 'Alto'.
 
    Returns:
        Tupla (color_hex, color_rgba).
    """
    table = {
        "Bajo":  (COLOR["green"],  COLOR["green_bg"]),
        "Medio": (COLOR["yellow"], COLOR["yellow_bg"]),
        "Alto":  (COLOR["red"],    COLOR["red_bg"]),
    }
    return table.get(risk, (COLOR["text"], COLOR["card"]))