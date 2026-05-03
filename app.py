import streamlit as st
from scanner import scan_domain
from headers import analyze_security_headers
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

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

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

    .result-box {
        background: #0D1B2A;
        border: 1px solid #1E3A5F;
        border-radius: 4px;
        padding: 1.2rem 1.5rem;
        font-family: 'Space Mono', monospace;
        font-size: 0.85rem;
        color: #00FFB2;
        margin-top: 1.5rem;
    }

    .result-box .label {
        color: #8892A4;
        font-size: 0.7rem;
        letter-spacing: 2px;
        margin-bottom: 0.3rem;
    }
</style>
""", unsafe_allow_html=True)

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown('<div class="badge">◈ HERRAMIENTA DE RECONOCIMIENTO PASIVO</div>', unsafe_allow_html=True)
st.markdown('<h1 class="main-title">🛡️ CyberScope AI</h1>', unsafe_allow_html=True)
st.markdown('<p class="subtitle">Análisis de exposición externa para dominios autorizados</p>', unsafe_allow_html=True)

st.markdown("""
<div class="info-box">
    CyberScope AI analiza la superficie de ataque visible de un dominio: cabeceras HTTP,
    puertos expuestos, configuración DNS, certificados TLS y vulnerabilidades comunes.
    Úsalo <strong>únicamente sobre dominios de tu propiedad</strong> o con autorización expresa.
</div>
""", unsafe_allow_html=True)

# ── Input ──────────────────────────────────────────────────────────────────────
domain = st.text_input(
    label="Dominio objetivo",
    placeholder="ejemplo.com",
    help="Introduce el dominio sin http:// ni barras finales",
)

analyze = st.button("⚡ Analizar dominio")

# ── Logic ──────────────────────────────────────────────────────────────────────
if analyze:
    if not domain.strip():
        st.warning("⚠️ Introduce un dominio antes de continuar.")
    else:
        clean_domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").rstrip("/")
        st.markdown(f"""
        <div class="result-box">
            <div class="label">ESTADO</div>
            ✅ Análisis iniciado para: <strong>{clean_domain}</strong>
        </div>
        """, unsafe_allow_html=True)

        result = scan_domain(clean_domain)

        st.subheader("Resultado del análisis básico")
        st.json(result)
       
        headers_result = analyze_security_headers(clean_domain)

        st.subheader("Análisis de cabeceras de seguridad")
        st.json(headers_result)

# ── Footer ─────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<p style="text-align:center; color:#3A4A5C; font-size:0.75rem; font-family:Space Mono, monospace;">'
    'CyberScope AI · Solo para uso ético y autorizado</p>',
    unsafe_allow_html=True
)
