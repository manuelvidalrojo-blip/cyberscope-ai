"""
CyberScope AI — interfaz web (Streamlit).

Flujo: login → análisis de un dominio autorizado → dashboard con puntuación,
resumen ejecutivo y recomendaciones → descarga de informes → historial.
"""

from __future__ import annotations

import json
import logging
import os
import time

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from modules import auth, storage
from modules.ai_report import generate_ai_summary
from modules.analysis import TargetNotAllowed, run_analysis
from modules.report import generate_html_report, generate_markdown_report
from modules.utils import esc, sanitize_domain, truncate

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cyberscope")

SESSION_TIMEOUT_MIN = int(os.getenv("SESSION_TIMEOUT_MIN", "30"))
CACHE_TTL_SECONDS = 600

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CyberScope AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ── Custom CSS (sin recursos externos) ─────────────────────────────────────────
st.markdown("""
<style>
    .main-title { font-family: monospace; font-size: 2.6rem; font-weight: 700; color: #00FFB2;
                  letter-spacing: -1px; margin-bottom: 0; }
    .subtitle   { color: #8892A4; font-size: 1rem; margin-top: 4px; margin-bottom: 1.5rem; }
    .badge      { display: inline-block; background: #0D1B2A; border: 1px solid #00FFB2; color: #00FFB2;
                  font-family: monospace; font-size: 0.65rem; padding: 2px 8px; border-radius: 2px;
                  margin-bottom: 1rem; letter-spacing: 2px; }
    .info-box   { background: #0D1B2A; border-left: 3px solid #00FFB2; padding: 1rem 1.2rem;
                  border-radius: 0 4px 4px 0; margin-bottom: 1.5rem; font-size: 0.9rem; color: #C8D6E5; }
    .score-card { background: #0D1B2A; border: 1px solid #1E3A5F; border-radius: 8px; padding: 1.5rem 2rem;
                  margin: 1rem 0; text-align: center; }
    .score-number { font-family: monospace; font-size: 4rem; font-weight: 700; line-height: 1; }
    .score-label  { font-family: monospace; font-size: 0.7rem; letter-spacing: 3px; color: #8892A4; margin-bottom: .8rem; }
    .risk-badge   { display: inline-block; font-family: monospace; font-size: 0.8rem; font-weight: 700;
                    letter-spacing: 2px; padding: 4px 14px; border-radius: 2px; margin-top: .8rem; }
    .risk-Bajo  { background: rgba(0,255,178,0.12); color: #00FFB2; border: 1px solid #00FFB2; }
    .risk-Medio { background: rgba(255,200,0,0.12); color: #FFC800; border: 1px solid #FFC800; }
    .risk-Alto  { background: rgba(255,75,75,0.12); color: #FF4B4B; border: 1px solid #FF4B4B; }
    .score-summary { color: #C8D6E5; font-size: 0.88rem; line-height: 1.6; margin-top: 0.8rem; }
    .section-title { font-family: monospace; font-size: 0.75rem; letter-spacing: 3px; color: #8892A4;
                     margin: 1.8rem 0 0.6rem 0; text-transform: uppercase; }
</style>
""", unsafe_allow_html=True)

SCORE_COLORS = {"Bajo": "#00FFB2", "Medio": "#FFC800", "Alto": "#FF4B4B"}
SEVERITY_ICON = {"Alta": "🔴", "Media": "🟠", "Baja": "⚪"}


# ══════════════════════════════════════════════════════════════════════════════
# INICIALIZACIÓN
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_resource
def _init_backend() -> bool:
    """Se ejecuta una vez por proceso: crea tablas y el administrador inicial."""
    storage.init_db()
    created = auth.bootstrap_admin_from_env()
    if created:
        log.info("Administrador inicial '%s' creado", created)
    return True


@st.cache_data(ttl=CACHE_TTL_SECONDS, show_spinner=False)
def _cached_analysis(domain: str) -> dict:
    """Caché de 10 min: repetir el mismo dominio no vuelve a lanzar peticiones."""
    return run_analysis(domain)


def client_ip() -> str | None:
    try:
        return st.context.ip_address
    except Exception:
        return None


def section(title: str) -> None:
    st.markdown(f'<p class="section-title">◈ {esc(title)}</p>', unsafe_allow_html=True)


def plain_field(label: str, value) -> None:
    """Muestra un valor externo como texto literal: st.write lo interpretaría como Markdown."""
    st.markdown(f"**{label}:**")
    st.text(value or "—")


# ══════════════════════════════════════════════════════════════════════════════
# AUTENTICACIÓN
# ══════════════════════════════════════════════════════════════════════════════

def current_user() -> dict | None:
    user = st.session_state.get("user")
    if not user:
        return None
    # Caducidad de sesión por inactividad
    if time.time() - st.session_state.get("last_activity", 0) > SESSION_TIMEOUT_MIN * 60:
        storage.audit("session_expired", user["username"], None, client_ip())
        st.session_state.clear()
        st.session_state["flash"] = "Tu sesión ha caducado por inactividad. Vuelve a iniciar sesión."
        return None
    st.session_state["last_activity"] = time.time()
    return user


def login_page() -> None:
    header()
    if st.session_state.get("flash"):
        st.info(st.session_state.pop("flash"))

    if auth.count_users() == 0:
        st.error(
            "No hay usuarios configurados. Define CYBERSCOPE_ADMIN_USER y CYBERSCOPE_ADMIN_PASSWORD "
            "en el fichero .env y reinicia la aplicación (ver README)."
        )
        return

    with st.form("login"):
        username = st.text_input("Usuario", max_chars=32)
        password = st.text_input("Contraseña", type="password", max_chars=128)
        submitted = st.form_submit_button("Iniciar sesión")

    if submitted:
        try:
            user = auth.authenticate(username, password, client_ip())
        except auth.AuthError as exc:
            st.error(str(exc))
            return
        st.session_state.clear()
        st.session_state["user"] = user
        st.session_state["last_activity"] = time.time()
        st.rerun()


def logout(user: dict) -> None:
    storage.audit("logout", user["username"], None, client_ip())
    st.session_state.clear()
    st.rerun()


# ══════════════════════════════════════════════════════════════════════════════
# PÁGINAS
# ══════════════════════════════════════════════════════════════════════════════

def header() -> None:
    st.markdown('<div class="badge">◈ RECONOCIMIENTO PASIVO · BLUE TEAM</div>', unsafe_allow_html=True)
    st.markdown('<h1 class="main-title">🛡️ CyberScope AI</h1>', unsafe_allow_html=True)
    st.markdown('<p class="subtitle">Análisis de exposición externa para dominios autorizados</p>', unsafe_allow_html=True)


def analyze_page(user: dict) -> None:
    header()
    st.markdown("""
    <div class="info-box">
        Analiza la superficie visible de un dominio: HTTPS, cabeceras de seguridad, certificado TLS,
        DNS y correo (SPF/DMARC), servicios expuestos (Shodan InternetDB) y subdominios públicos (crt.sh).
        Todo es <strong>pasivo</strong>: no se escanean puertos ni se lanzan pruebas intrusivas.
    </div>
    """, unsafe_allow_html=True)

    with st.form("analyze"):
        domain_input = st.text_input("Dominio objetivo", placeholder="ejemplo.com", max_chars=300,
                                     help="Solo el dominio. Si pegas una URL, se limpia automáticamente.")
        authorized = st.checkbox("Confirmo que este dominio es mío o tengo autorización expresa para analizarlo.")
        submitted = st.form_submit_button("⚡ Analizar dominio")

    if submitted:
        start_analysis(user, domain_input, authorized)

    analysis = st.session_state.get("last_analysis")
    if analysis:
        render_results(analysis, user)


def start_analysis(user: dict, domain_input: str, authorized: bool) -> None:
    domain = sanitize_domain(domain_input)
    if not domain:
        st.warning("⚠️ Introduce un dominio antes de continuar.")
        return
    if not authorized:
        st.warning("⚠️ Debes confirmar que tienes autorización para analizar el dominio.")
        return

    allowed, used, maximum = auth.rate_limit_status(user["username"])
    if not allowed:
        storage.audit("analysis_rate_limited", user["username"], domain, client_ip())
        st.error(f"⛔ Has alcanzado el límite de {maximum} análisis en "
                 f"{os.getenv('RATE_LIMIT_WINDOW_MIN', '10')} minutos. Espera un poco.")
        return

    storage.audit("analysis_requested", user["username"], f"{domain} (autorización confirmada)", client_ip())

    try:
        with st.spinner(f"Analizando {domain}… (10-25 s)"):
            analysis = dict(_cached_analysis(domain))
            analysis["ai_summary"] = generate_ai_summary(analysis)
    except TargetNotAllowed as exc:
        storage.audit("analysis_rejected", user["username"], f"{domain}: {exc}", client_ip())
        st.error(f"⛔ {exc}")
        return
    except Exception:
        # Nunca mostramos trazas internas al usuario; quedan en el log del servidor
        log.exception("Error inesperado analizando %s", domain)
        st.error("Se produjo un error interno durante el análisis. Inténtalo de nuevo más tarde.")
        return

    analysis["analyst"] = user["username"]
    storage.save_analysis(user["username"], analysis)
    storage.audit("analysis_completed", user["username"], f"{domain} → {analysis['score']['global_score']}/100", client_ip())
    st.session_state["last_analysis"] = analysis


def history_page(user: dict) -> None:
    st.header("📈 Historial de análisis")
    is_admin = user["role"] == "admin"
    st.caption("Ves los análisis de todos los usuarios." if is_admin else "Solo ves tus propios análisis.")

    rows = storage.list_analyses(username=None if is_admin else user["username"])
    if not rows:
        st.info("Todavía no hay análisis guardados.")
        return

    df = pd.DataFrame(rows)
    domains = sorted(df["domain"].unique())
    domain = st.selectbox("Dominio", domains)
    sub = df[df["domain"] == domain].sort_values("ts")

    section(f"Evolución de la puntuación · {domain}")
    chart = sub.assign(fecha=pd.to_datetime(sub["ts"])).set_index("fecha")[["score"]]
    st.line_chart(chart, y="score", height=250)

    cols = ["id", "ts", "score", "risk"] + (["username"] if is_admin else [])
    st.dataframe(sub[cols].sort_values("ts", ascending=False), hide_index=True, width="stretch")

    selected = st.selectbox("Ver un análisis anterior", sub.sort_values("ts", ascending=False)["id"].tolist(),
                            format_func=lambda i: f"#{i} · {sub.loc[sub['id'] == i, 'ts'].iloc[0]}")
    if st.button("Abrir análisis"):
        st.session_state["history_view"] = selected

    view_id = st.session_state.get("history_view")
    if view_id:
        analysis = storage.get_analysis(view_id, username=None if is_admin else user["username"])
        if analysis is None:
            st.error("No tienes acceso a ese análisis.")   # control de acceso por propietario
        else:
            render_results(analysis, user)


def admin_page(user: dict) -> None:
    if user["role"] != "admin":                        # doble comprobación en servidor
        storage.audit("access_denied", user["username"], "admin_page", client_ip())
        st.error("⛔ No tienes permisos para ver esta página.")
        return

    st.header("🔐 Administración")

    section("Usuarios")
    st.dataframe(pd.DataFrame(auth.list_users()), hide_index=True, width="stretch")

    with st.form("new_user", clear_on_submit=True):
        st.subheader("Crear usuario")
        new_name = st.text_input("Usuario", max_chars=32)
        new_pass = st.text_input("Contraseña (mín. 12 caracteres, letras y números)", type="password")
        new_role = st.selectbox("Rol", auth.ROLES, index=1)
        if st.form_submit_button("Crear"):
            try:
                auth.create_user(new_name.strip(), new_pass, new_role)
                storage.audit("user_created", user["username"], f"{new_name} ({new_role})", client_ip())
                st.success(f"Usuario '{new_name}' creado.")
            except auth.AuthError as exc:
                st.error(str(exc))

    others = [u["username"] for u in auth.list_users() if u["username"] != user["username"]]
    if others:
        c1, c2 = st.columns([3, 1])
        target = c1.selectbox("Activar / desactivar usuario", others)
        if c2.button("Cambiar estado"):
            active = next(u["active"] for u in auth.list_users() if u["username"] == target)
            auth.set_active(target, not active)
            storage.audit("user_toggled", user["username"], f"{target} → {'inactivo' if active else 'activo'}", client_ip())
            st.rerun()

    section("Registro de auditoría (últimos 200 eventos)")
    st.dataframe(pd.DataFrame(storage.list_audit()), hide_index=True, width="stretch")


# ══════════════════════════════════════════════════════════════════════════════
# RESULTADOS
# ══════════════════════════════════════════════════════════════════════════════

def render_results(a: dict, user: dict) -> None:
    score = a["score"]
    risk = score["risk_level"]
    color = SCORE_COLORS.get(risk, "#ffffff")

    # ── 1. Puntuación global ───────────────────────────────────────────────────
    st.markdown(f"""
    <div class="score-card">
        <div class="score-label">PUNTUACIÓN DE SEGURIDAD · {esc(a['domain']).upper()}</div>
        <div class="score-number" style="color:{color};">{int(score['global_score'])}<span style="font-size:1.5rem;color:#3A4A5C;">/100</span></div>
        <span class="risk-badge risk-{esc(risk)}">RIESGO {esc(risk.upper())}</span>
        <div class="score-summary">{esc(score['summary'])}</div>
    </div>
    """, unsafe_allow_html=True)
    st.caption(f"Analizado el {a['timestamp']} UTC en {a.get('duration_s')} s · IPs: {', '.join(a.get('ips', []))}")

    # ── 2. Desglose ────────────────────────────────────────────────────────────
    b, mx = score["breakdown"], score["max_points"]
    c = st.columns(5)
    c[0].metric("HTTPS", f"{b['https']:.0f}/{mx['https']}")
    c[1].metric("Cabeceras", f"{b['headers']:.0f}/{mx['headers']}")
    c[2].metric("TLS", f"{b['tls']:.0f}/{mx['tls']}")
    c[3].metric("Correo", f"{b['email']:.0f}/{mx['email']}")
    c[4].metric("Exposición", f"{b['exposure_penalty']}")

    # ── 3. Resumen ejecutivo (IA o reglas) ─────────────────────────────────────
    ai = a.get("ai_summary")
    if ai:
        section("Resumen ejecutivo")
        if ai["source"] == "claude":
            st.caption(f"🤖 Generado con IA ({ai.get('model')}). Revísalo antes de compartirlo.")
        else:
            st.caption(f"⚙️ {ai.get('note') or 'Resumen generado por reglas (sin IA).'}")
        with st.container(border=True):
            st.markdown(ai["text"])          # Markdown sin HTML (unsafe_allow_html desactivado)

    # ── 4. Recomendaciones priorizadas ─────────────────────────────────────────
    section("Recomendaciones priorizadas")
    recs = score.get("recommendations", [])
    if not recs:
        st.success("✅ No hay recomendaciones pendientes. ¡Configuración excelente!")
    for r in recs:
        st.markdown(f"{SEVERITY_ICON[r['severity']]} **{r['severity']} · {r['area']}** — {esc(r['text'])}")

    # ── 5. Detalle por módulo ──────────────────────────────────────────────────
    section("Detalle técnico")
    tabs = st.tabs(["Conectividad", "Cabeceras", "Certificado TLS", "DNS y correo", "Exposición", "Subdominios"])

    scan = a["scan"]
    with tabs[0]:
        if scan.get("error"):
            st.error(scan["error"])
        col1, col2, col3 = st.columns(3)
        col1.metric("HTTP", str(scan.get("http_status") or "N/A"))
        col2.metric("HTTPS", str(scan.get("https_status") or "N/A"))
        col3.metric("Redirige a HTTPS", "✅ Sí" if scan.get("redirects_to_https") else "❌ No")
        plain_field("Tecnologías detectadas", ", ".join(scan.get("technologies", [])))

    headers = a["headers"]
    with tabs[1]:
        if headers.get("error"):
            st.error(headers["error"])
        st.dataframe(pd.DataFrame([
            {"Cabecera": h, "Estado": "✅ Presente" if v else "❌ Ausente", "Valor": truncate(v, 120) if v else "—"}
            for h, v in headers["headers_found"].items()
        ]), hide_index=True, width="stretch")

    tls = a["tls"]
    with tabs[2]:
        if tls.get("error"):
            st.error(tls["error"])
        else:
            col1, col2, col3 = st.columns(3)
            col1.metric("Días hasta caducar", tls.get("days_left"))
            col2.metric("Versión", tls.get("tls_version") or "—")
            col3.metric("Confiable", "✅ Sí" if tls.get("trusted") else "❌ No")
            plain_field("Emisor", tls.get("issuer"))
            st.write("**Válido:**", f"{tls.get('not_before')} → {tls.get('not_after')}")
            plain_field("Nombres (SAN)", ", ".join(tls.get("san", [])[:20]))

    dns = a["dns"]
    with tabs[3]:
        if dns.get("error"):
            st.error(dns["error"])
        else:
            col1, col2 = st.columns(2)
            col1.metric("SPF", f"✅ {dns.get('spf_all') or ''}" if dns.get("spf_found") else "❌ No encontrado")
            col2.metric("DMARC", f"✅ p={dns.get('dmarc_policy')}" if dns.get("dmarc_found") else "❌ No encontrado")
            for tipo, clave in [("A", "a_records"), ("AAAA", "aaaa_records"), ("MX", "mx_records"), ("NS", "ns_records")]:
                plain_field(tipo, ", ".join(dns.get(clave, [])))
            if dns.get("dmarc_record"):
                st.code(dns["dmarc_record"], language=None)

    exp = a["exposure"]
    with tabs[4]:
        st.caption(exp.get("source", ""))
        if exp.get("error"):
            st.warning(exp["error"])
        else:
            st.write("**Puertos observados:**", ", ".join(map(str, exp.get("open_ports", []))) or "Ninguno registrado")
            for item in exp.get("risky_ports", []):
                st.error(f"Puerto {item['port']} — {item['service']}")
            if exp.get("vulns"):
                st.write("**CVE asociadas:**", ", ".join(exp["vulns"][:30]))

    sub = a["subdomains"]
    with tabs[5]:
        st.caption(sub.get("source", ""))
        if sub.get("error"):
            st.warning(sub["error"])
        else:
            st.write(f"**{sub.get('total', 0)} subdominios** encontrados" + (" (lista recortada)" if sub.get("truncated") else ""))
            if sub.get("subdomains"):
                st.dataframe(pd.DataFrame({"Subdominio": sub["subdomains"]}), hide_index=True, height=250)

    # ── 6. Descargas ───────────────────────────────────────────────────────────
    section("Informes")
    c1, c2, c3 = st.columns(3)
    name = f"cyberscope_{a['domain']}_{a['timestamp'][:10]}"
    c1.download_button("📄 Informe HTML", generate_html_report(a, ai, a.get("analyst")),
                       file_name=f"{name}.html", mime="text/html")
    c2.download_button("📝 Informe Markdown", generate_markdown_report(a, ai),
                       file_name=f"{name}.md", mime="text/markdown")
    c3.download_button("🧾 Datos JSON", json.dumps(a, ensure_ascii=False, indent=2),
                       file_name=f"{name}.json", mime="application/json")

    with st.expander("🔍 Ver datos técnicos JSON"):
        st.json(a, expanded=False)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    _init_backend()
    user = current_user()
    if not user:
        login_page()
        return

    with st.sidebar:
        st.markdown(f"👤 **{user['username']}** · {user['role']}")
        pages = ["🔎 Analizar", "📈 Historial"] + (["🔐 Administración"] if user["role"] == "admin" else [])
        page = st.radio("Navegación", pages, label_visibility="collapsed")
        if st.button("Cerrar sesión"):
            logout(user)
        st.caption(f"La sesión caduca tras {SESSION_TIMEOUT_MIN} min de inactividad.")

    if page.endswith("Analizar"):
        analyze_page(user)
    elif page.endswith("Historial"):
        history_page(user)
    else:
        admin_page(user)

    st.markdown("---")
    st.markdown(
        '<p style="text-align:center;color:#3A4A5C;font-size:0.75rem;font-family:monospace;">'
        'CyberScope AI v2.0 · Solo para uso ético y autorizado</p>',
        unsafe_allow_html=True,
    )


main()
