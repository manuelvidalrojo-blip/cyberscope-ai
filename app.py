import streamlit as st

 
from scanner import scan_domain
from headers import analyze_security_headers
from scoring import calculate_global_score
from ai_report import generate_html_report
# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberScope AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)
 
# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Inter:wght@300;400;600&display=swap');
 
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
 
    .main-title {
        font-family: 'Space Mono', monospace;
        font-size: 2.8rem;
        font-weight: 700;
        color: #00FFB2;
        letter-spacing: -1px;
        margin-bottom: 0;
    }
    .subtitle {
        color: #8892A4;
        font-size: 1rem;
        font-weight: 300;
        margin-top: 4px;
        margin-bottom: 2rem;
    }
    .badge {
        display: inline-block;
        background: #0D1B2A;
        border: 1px solid #00FFB2;
        color: #00FFB2;
        font-family: 'Space Mono', monospace;
        font-size: 0.65rem;
        padding: 2px 8px;
        border-radius: 2px;
        margin-bottom: 1.5rem;
        letter-spacing: 2px;
    }
    .info-box {
        background: #0D1B2A;
        border-left: 3px solid #00FFB2;
        padding: 1rem 1.2rem;
        border-radius: 0 4px 4px 0;
        margin-bottom: 1.5rem;
        font-size: 0.9rem;
        color: #C8D6E5;
        line-height: 1.6;
    }
    .stTextInput > div > div > input {
        font-family: 'Space Mono', monospace;
        font-size: 0.9rem;
        background-color: #0D1B2A;
        border: 1px solid #1E3A5F;
        color: #E0E8F0;
        border-radius: 4px;
    }
    .stTextInput > div > div > input:focus {
        border-color: #00FFB2;
        box-shadow: 0 0 0 2px rgba(0, 255, 178, 0.15);
    }
    .stButton > button {
        font-family: 'Space Mono', monospace;
        font-size: 0.85rem;
        font-weight: 700;
        letter-spacing: 1px;
        background-color: #00FFB2;
        color: #0A0F1E;
        border: none;
        border-radius: 4px;
        padding: 0.6rem 2rem;
        width: 100%;
        transition: all 0.2s ease;
    }
    .stButton > button:hover {
        background-color: #00E0A0;
        transform: translateY(-1px);
        box-shadow: 0 4px 20px rgba(0, 255, 178, 0.3);
    }
 
    /* Tarjeta de score global */
    .score-card {
        background: #0D1B2A;
        border: 1px solid #1E3A5F;
        border-radius: 8px;
        padding: 1.8rem 2rem;
        margin: 1.5rem 0;
        text-align: center;
    }
    .score-number {
        font-family: 'Space Mono', monospace;
        font-size: 4rem;
        font-weight: 700;
        line-height: 1;
        margin-bottom: 0.3rem;
    }
    .score-label {
        font-family: 'Space Mono', monospace;
        font-size: 0.7rem;
        letter-spacing: 3px;
        color: #8892A4;
        margin-bottom: 1rem;
    }
    .risk-badge {
        display: inline-block;
        font-family: 'Space Mono', monospace;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 2px;
        padding: 4px 14px;
        border-radius: 2px;
        margin-bottom: 1rem;
    }
    .risk-bajo    { background: rgba(0,255,178,0.12); color: #00FFB2; border: 1px solid #00FFB2; }
    .risk-medio   { background: rgba(255,200,0,0.12); color: #FFC800; border: 1px solid #FFC800; }
    .risk-alto    { background: rgba(255,75,75,0.12);  color: #FF4B4B; border: 1px solid #FF4B4B; }
    .score-summary {
        color: #C8D6E5;
        font-size: 0.88rem;
        line-height: 1.6;
        margin-top: 0.8rem;
    }
 
    /* Tabla de cabeceras */
    .header-row {
        display: flex;
        align-items: center;
        padding: 0.5rem 0;
        border-bottom: 1px solid #1E3A5F;
        font-size: 0.85rem;
    }
    .header-name  { flex: 2; font-family: 'Space Mono', monospace; color: #C8D6E5; }
    .header-state { flex: 1; text-align: center; }
    .header-value { flex: 3; color: #8892A4; font-size: 0.78rem; word-break: break-all; }
    .pill-ok  { background: rgba(0,255,178,0.12); color: #00FFB2; border: 1px solid #00FFB2;
                padding: 2px 10px; border-radius: 20px; font-size: 0.7rem; font-family: 'Space Mono', monospace; }
    .pill-ko  { background: rgba(255,75,75,0.12);  color: #FF4B4B; border: 1px solid #FF4B4B;
                padding: 2px 10px; border-radius: 20px; font-size: 0.7rem; font-family: 'Space Mono', monospace; }
 
    .section-title {
        font-family: 'Space Mono', monospace;
        font-size: 0.7rem;
        letter-spacing: 3px;
        color: #8892A4;
        margin: 1.8rem 0 0.8rem 0;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)
 
 
# ══════════════════════════════════════════════════════════════════════════════
# HEADER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown('<div class="badge">◈ HERRAMIENTA DE RECONOCIMIENTO PASIVO</div>', unsafe_allow_html=True)
st.markdown('<h1 class="main-title">🛡️ CyberScope AI</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Análisis de exposición externa para dominios autorizados</p>', unsafe_allow_html=True)
 
st.markdown("""
<div class="info-box">
    CyberScope AI analiza la superficie de ataque visible de un dominio: cabeceras HTTP,
    configuración HTTPS y políticas de seguridad.
    Úsalo <strong>únicamente sobre dominios de tu propiedad</strong> o con autorización expresa.
</div>
""", unsafe_allow_html=True)
 
 
# ══════════════════════════════════════════════════════════════════════════════
# INPUT
# ══════════════════════════════════════════════════════════════════════════════
domain = st.text_input(
    label="Dominio objetivo",
    placeholder="ejemplo.com",
    help="Introduce el dominio sin http:// ni barras finales",
)
 
analyze = st.button("⚡ Analizar dominio")
 
 
# ══════════════════════════════════════════════════════════════════════════════
# ANÁLISIS
# ══════════════════════════════════════════════════════════════════════════════
if analyze:
 
    # Validación básica
    if not domain.strip():
        st.warning("⚠️ Introduce un dominio antes de continuar.")
 
    else:
        # Limpiamos el dominio
        clean_domain = (
            domain.strip().lower()
            .removeprefix("http://")
            .removeprefix("https://")
            .rstrip("/")
        )
 
        # ── Ejecutamos los tres módulos con spinner ────────────────────────────
        with st.spinner(f"Analizando {clean_domain}…"):
            scan_result    = scan_domain(clean_domain)
            headers_result = analyze_security_headers(clean_domain)
            score_result   = calculate_global_score(scan_result, headers_result)
 
        # ── 1. TARJETA DE SCORE GLOBAL ─────────────────────────────────────────
        score      = score_result["global_score"]
        risk       = score_result["risk_level"]
        summary    = score_result["summary"]
 
        # Color del score según riesgo
        score_color = {"Bajo": "#00FFB2", "Medio": "#FFC800", "Alto": "#FF4B4B"}.get(risk, "#ffffff")
        risk_class  = {"Bajo": "risk-bajo", "Medio": "risk-medio",  "Alto": "risk-alto"}.get(risk, "")
 
        st.markdown(f"""
        <div class="score-card">
            <div class="score-label">PUNTUACIÓN DE SEGURIDAD GLOBAL</div>
            <div class="score-number" style="color:{score_color};">{score}<span style="font-size:1.5rem;color:#3A4A5C;">/100</span></div>
            <br>
            <span class="risk-badge {risk_class}">RIESGO {risk.upper()}</span>
            <div class="score-summary">{summary}</div>
        </div>
        """, unsafe_allow_html=True)
 
        # ── 2. TRES MÉTRICAS RÁPIDAS ───────────────────────────────────────────
        st.markdown('<p class="section-title">◈ Conectividad</p>', unsafe_allow_html=True)
 
        col1, col2, col3 = st.columns(3)
 
        http_status  = scan_result.get("http_status")
        https_status = scan_result.get("https_status")
        uses_https   = scan_result.get("uses_https", False)
 
        col1.metric(
            label="HTTP Status",
            value=str(http_status) if http_status else "N/A",
        )
        col2.metric(
            label="HTTPS Status",
            value=str(https_status) if https_status else "N/A",
        )
        col3.metric(
            label="HTTPS activo",
            value="✅ Sí" if uses_https else "❌ No",
        )
 
        # ── 3. TABLA DE CABECERAS ──────────────────────────────────────────────
        st.markdown('<p class="section-title">◈ Cabeceras de seguridad</p>', unsafe_allow_html=True)
 
        headers_found = headers_result.get("headers_found", {})
 
        # Construimos las filas HTML una a una
        filas_html = ""
        for cabecera, valor in headers_found.items():
            if valor:
                estado_html = '<span class="pill-ok">Presente</span>'
                valor_texto = valor if len(valor) <= 80 else valor[:77] + "…"
            else:
                estado_html = '<span class="pill-ko">Ausente</span>'
                valor_texto = "—"
 
            filas_html += f"""
            <div class="header-row">
                <div class="header-name">{cabecera}</div>
                <div class="header-state">{estado_html}</div>
                <div class="header-value">{valor_texto}</div>
            </div>
            """
 
        st.markdown(f"""
        <div style="background:#0D1B2A; border:1px solid #1E3A5F; border-radius:6px; padding:1rem 1.2rem;">
            <div class="header-row" style="border-bottom:1px solid #2A4A6F; margin-bottom:0.3rem;">
                <div class="header-name"  style="color:#8892A4; font-size:0.7rem; letter-spacing:2px;">CABECERA</div>
                <div class="header-state" style="color:#8892A4; font-size:0.7rem; letter-spacing:2px;">ESTADO</div>
                <div class="header-value" style="color:#8892A4; font-size:0.7rem; letter-spacing:2px;">VALOR</div>
            </div>
            {filas_html}
        </div>
        """, unsafe_allow_html=True)
 
        # ── 4. RECOMENDACIONES ─────────────────────────────────────────────────
        recommendations = headers_result.get("recommendations", [])
 
        if recommendations:
            st.markdown('<p class="section-title">◈ Recomendaciones</p>', unsafe_allow_html=True)
            for rec in recommendations:
                st.warning(rec)
        else:
            st.success("✅ No hay recomendaciones pendientes. ¡Configuración excelente!")
 
        # Aviso adicional si no hay redirección HTTP → HTTPS
        if not scan_result.get("redirects_to_https") and not scan_result.get("error"):
            st.info("ℹ️ El dominio no redirige automáticamente de HTTP a HTTPS. "
                    "Considera añadir una redirección 301 en tu servidor.")
        # ── 5. GENERAR INFORME HTML ────────────────────────────────────────────
        html_report = generate_html_report(
            clean_domain,
            scan_result,
            headers_result,
            score_result
        )

        st.download_button(
            label="📄 Descargar informe HTML",
            data=html_report,
            file_name=f"cyberscope_report_{clean_domain}.html",
            mime="text/html"
        )
        
        
                        
        # ── 6. DATOS TÉCNICOS (desplegable) ────────────────────────────────────
        with st.expander("🔍 Ver datos técnicos JSON"):
            st.caption("Resultado del escaneo HTTP/HTTPS")
            st.json(scan_result)
 
            st.caption("Resultado del análisis de cabeceras")
            st.json(headers_result)
 
            st.caption("Resultado de puntuación global")
            st.json(score_result)
 
 
# ══════════════════════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(
    '<p style="text-align:center;color:#3A4A5C;font-size:0.75rem;font-family:Space Mono,monospace;">'
    'CyberScope AI · Solo para uso ético y autorizado</p>',
    unsafe_allow_html=True,
)
 