"""
report.py
---------
Generación de informes descargables: HTML autocontenido y Markdown.

Seguridad: TODO valor que procede del dominio analizado (cabeceras,
registros DNS, certificado, subdominios...) se escapa con esc(). En la
Práctica 1 se insertaba tal cual, lo que permitía que un dominio malicioso
inyectara HTML/JavaScript en el informe. Además el informe incluye una
Content-Security-Policy que bloquea scripts y recursos externos.
"""

from __future__ import annotations

from modules.utils import esc, truncate

RISK_COLORS = {"Bajo": "#0f9d58", "Medio": "#e6a700", "Alto": "#d93025"}
SEVERITY_COLORS = {"Alta": "#d93025", "Media": "#e6a700", "Baja": "#5f6b7a"}


# ══════════════════════════════════════════════════════════════════════════════
# HTML
# ══════════════════════════════════════════════════════════════════════════════

def generate_html_report(analysis: dict, ai_summary: dict | None = None, author: str | None = None) -> str:
    """Devuelve el informe completo como HTML autocontenido (sin JS ni recursos externos)."""
    a = analysis
    score = a["score"]
    color = RISK_COLORS.get(score["risk_level"], "#333")

    sections = [
        _summary_section(a, score, color, ai_summary),
        _breakdown_section(score),
        _recommendations_section(score.get("recommendations", [])),
        _connectivity_section(a["scan"]),
        _headers_section(a["headers"]),
        _tls_section(a["tls"]),
        _dns_section(a["dns"]),
        _exposure_section(a["exposure"]),
        _subdomains_section(a["subdomains"]),
    ]

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberScope AI · Informe de {esc(a['domain'])}</title>
<style>{_STYLES}</style>
</head>
<body>
<header>
  <div class="brand">🛡️ CyberScope AI</div>
  <h1>Informe de exposición externa</h1>
  <p class="meta">Dominio: <strong>{esc(a['domain'])}</strong> · IPs: {esc(', '.join(a.get('ips', [])))}<br>
  Fecha (UTC): {esc(a['timestamp'])} · Duración: {esc(a.get('duration_s'))} s{(' · Analista: ' + esc(author)) if author else ''}</p>
</header>
{''.join(sections)}
<footer>Análisis pasivo generado por CyberScope AI. Uso exclusivo sobre dominios propios o con autorización expresa.
Para guardarlo en PDF usa «Imprimir → Guardar como PDF» en el navegador.</footer>
</body>
</html>"""


def _summary_section(a, score, color, ai_summary) -> str:
    ai_html = ""
    if ai_summary:
        origen = (f"Generado con IA ({esc(ai_summary.get('model'))})" if ai_summary.get("source") == "claude"
                  else "Generado por reglas (sin IA)")
        ai_html = f"""<div class="ai"><div class="tag">{origen}</div>{_markdown_to_html(ai_summary.get('text', ''))}</div>"""
    return f"""
<section>
  <div class="score" style="border-color:{color}">
    <div class="num" style="color:{color}">{esc(score['global_score'])}<small>/100</small></div>
    <div class="risk" style="background:{color}">RIESGO {esc(str(score['risk_level']).upper())}</div>
  </div>
  <p>{esc(score.get('summary'))}</p>
  {ai_html}
</section>"""


def _breakdown_section(score) -> str:
    labels = {"https": "HTTPS y redirección", "headers": "Cabeceras de seguridad",
              "tls": "Certificado TLS", "email": "Correo (SPF/DMARC)"}
    rows = "".join(
        f"<tr><td>{labels[k]}</td><td>{round(score['breakdown'][k], 1)} / {score['max_points'][k]}</td></tr>"
        for k in labels
    )
    rows += f"<tr><td>Penalización por exposición</td><td>{score['breakdown']['exposure_penalty']}</td></tr>"
    return _section("Desglose de la puntuación", f"<table>{rows}</table>")


def _recommendations_section(recs) -> str:
    if not recs:
        return _section("Recomendaciones", "<p>✅ No hay recomendaciones pendientes.</p>")
    items = "".join(
        f'<li><span class="sev" style="background:{SEVERITY_COLORS[r["severity"]]}">{esc(r["severity"])}</span> '
        f'<strong>{esc(r["area"])}:</strong> {esc(r["text"])}</li>'
        for r in recs
    )
    return _section("Recomendaciones priorizadas", f"<ol class='recs'>{items}</ol>")


def _connectivity_section(scan) -> str:
    rows = [
        ("Estado HTTP", scan.get("http_status") or "N/A"),
        ("Estado HTTPS", scan.get("https_status") or "N/A"),
        ("HTTPS activo", _yes_no(scan.get("uses_https"))),
        ("Redirige HTTP → HTTPS", _yes_no(scan.get("redirects_to_https"))),
        ("Tecnologías detectadas", ", ".join(scan.get("technologies", [])) or "—"),
    ]
    body = _kv_table(rows)
    if scan.get("error"):
        body = f"<p class='err'>{esc(scan['error'])}</p>" + body
    return _section("Conectividad y tecnologías", body)


def _headers_section(headers) -> str:
    rows = "".join(
        f"<tr><td><code>{esc(name)}</code></td><td>{_pill(bool(value))}</td><td>{esc(truncate(value, 150)) if value else '—'}</td></tr>"
        for name, value in headers.get("headers_found", {}).items()
    )
    err = f"<p class='err'>{esc(headers['error'])}</p>" if headers.get("error") else ""
    return _section("Cabeceras de seguridad", f"{err}<table><tr><th>Cabecera</th><th>Estado</th><th>Valor</th></tr>{rows}</table>")


def _tls_section(tls) -> str:
    if tls.get("error"):
        return _section("Certificado TLS", f"<p class='err'>{esc(tls['error'])}</p>")
    rows = [
        ("Emisor", tls.get("issuer")), ("Sujeto", tls.get("subject")),
        ("Válido desde", tls.get("not_before")), ("Válido hasta", tls.get("not_after")),
        ("Días restantes", tls.get("days_left")), ("Versión TLS", tls.get("tls_version")),
        ("Cifrado", tls.get("cipher")), ("Nombres (SAN)", ", ".join(tls.get("san", [])[:15])),
    ]
    return _section("Certificado TLS", _kv_table(rows))


def _dns_section(dns) -> str:
    if dns.get("error"):
        return _section("DNS y correo", f"<p class='err'>{esc(dns['error'])}</p>")
    rows = [
        ("A", ", ".join(dns.get("a_records", [])) or "—"),
        ("AAAA", ", ".join(dns.get("aaaa_records", [])) or "—"),
        ("MX", ", ".join(dns.get("mx_records", [])) or "—"),
        ("NS", ", ".join(dns.get("ns_records", [])) or "—"),
        ("SPF", truncate(dns.get("spf_record"), 200) if dns.get("spf_found") else "No encontrado"),
        ("DMARC", truncate(dns.get("dmarc_record"), 200) if dns.get("dmarc_found") else "No encontrado"),
    ]
    return _section("DNS y correo", _kv_table(rows))


def _exposure_section(exp) -> str:
    if exp.get("error"):
        return _section("Servicios expuestos", f"<p class='err'>{esc(exp['error'])}</p>")
    rows = [
        ("Puertos observados", ", ".join(str(p) for p in exp.get("open_ports", [])) or "Ninguno registrado"),
        ("Puertos de riesgo", ", ".join(f"{r['port']} ({r['service']})" for r in exp.get("risky_ports", [])) or "Ninguno"),
        ("CVE asociadas", ", ".join(exp.get("vulns", [])[:30]) or "Ninguna"),
    ]
    return _section("Servicios expuestos", f"<p class='note'>Fuente: {esc(exp.get('source'))}</p>" + _kv_table(rows))


def _subdomains_section(sub) -> str:
    if sub.get("error"):
        return _section("Subdominios públicos", f"<p class='err'>{esc(sub['error'])}</p>")
    names = sub.get("subdomains", [])
    extra = f" (se muestran {len(names)})" if sub.get("truncated") else ""
    body = f"<p class='note'>{sub.get('total', 0)} encontrados en {esc(sub.get('source'))}{extra}.</p>"
    if names:
        body += "<ul class='cols'>" + "".join(f"<li>{esc(n)}</li>" for n in names) + "</ul>"
    return _section("Subdominios públicos", body)


# ── Helpers HTML ───────────────────────────────────────────────────────────────

def _section(title: str, body: str) -> str:
    return f"<section><h2>{esc(title)}</h2>{body}</section>"


def _kv_table(rows) -> str:
    return "<table>" + "".join(f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>" for k, v in rows) + "</table>"


def _pill(ok: bool) -> str:
    return '<span class="ok">Presente</span>' if ok else '<span class="ko">Ausente</span>'


def _yes_no(value) -> str:
    return "Sí" if value else "No"


def _markdown_to_html(text: str) -> str:
    """Conversión mínima y SEGURA de Markdown (se escapa primero, luego se formatea)."""
    import re
    out, in_list = [], False
    for raw in (text or "").splitlines():
        line = esc(raw.strip())
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
        is_item = re.match(r"^(?:[-*]|\d+\.)\s+(.*)", line)
        if is_item:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{is_item.group(1)}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.startswith("#"):
            out.append(f"<h3>{line.lstrip('#').strip()}</h3>")
        elif line:
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append("</ul>")
    return "".join(out)


_STYLES = """
body{font-family:Segoe UI,Arial,sans-serif;max-width:920px;margin:0 auto;padding:24px;color:#1f2933;background:#fff;line-height:1.5}
header{border-bottom:3px solid #00b386;margin-bottom:16px}.brand{font-weight:700;color:#00b386}
h1{margin:4px 0}h2{font-size:1.1rem;border-left:4px solid #00b386;padding-left:8px;margin-top:28px}
.meta,.note{color:#5f6b7a;font-size:.9rem}.err{color:#d93025}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{border-bottom:1px solid #e4e7eb;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-word}
th{width:28%;color:#3e4c59}.score{display:flex;align-items:center;gap:20px;border:2px solid;border-radius:8px;padding:16px}
.num{font-size:3rem;font-weight:700}.num small{font-size:1.2rem;color:#9aa5b1}.risk{color:#fff;padding:4px 12px;border-radius:4px;font-weight:700}
.ai{background:#f5f7fa;border-radius:8px;padding:12px 16px;margin-top:12px}.tag{font-size:.75rem;color:#5f6b7a;text-transform:uppercase}
.sev{color:#fff;font-size:.75rem;padding:1px 8px;border-radius:10px}.recs li{margin-bottom:6px}
.ok{color:#0f9d58;font-weight:600}.ko{color:#d93025;font-weight:600}.cols{columns:2;font-size:.85rem}
footer{margin-top:32px;font-size:.8rem;color:#9aa5b1;border-top:1px solid #e4e7eb;padding-top:8px}
@media print{body{padding:0}section{break-inside:avoid}}
"""


# ══════════════════════════════════════════════════════════════════════════════
# MARKDOWN
# ══════════════════════════════════════════════════════════════════════════════

def generate_markdown_report(analysis: dict, ai_summary: dict | None = None) -> str:
    """Informe en Markdown, útil para pegarlo en un ticket o en documentación."""
    a, s = analysis, analysis["score"]

    def md(value) -> str:
        # Evita que valores externos rompan la tabla o inyecten enlaces/HTML
        return esc(str(value if value is not None else "—")).replace("|", "\\|").replace("\n", " ")

    lines = [
        f"# Informe CyberScope AI — {md(a['domain'])}",
        "",
        f"- **Fecha (UTC):** {md(a['timestamp'])}",
        f"- **Puntuación:** {s['global_score']}/100 — riesgo **{s['risk_level']}**",
        f"- **IPs:** {md(', '.join(a.get('ips', [])))}",
        "",
        md(s.get("summary")),
        "",
    ]
    if ai_summary:
        origen = "IA (" + str(ai_summary.get("model")) + ")" if ai_summary.get("source") == "claude" else "reglas (sin IA)"
        lines += [f"## Resumen ejecutivo — generado por {origen}", "", ai_summary.get("text", ""), ""]

    lines += ["## Recomendaciones", ""]
    lines += [f"{i}. **[{r['severity']}] {r['area']}:** {md(r['text'])}" for i, r in enumerate(s["recommendations"], 1)] \
        or ["Sin recomendaciones pendientes."]

    lines += ["", "## Cabeceras de seguridad", "", "| Cabecera | Estado |", "|---|---|"]
    lines += [f"| {h} | {'Presente' if v else 'Ausente'} |" for h, v in a["headers"]["headers_found"].items()]

    tls, dns, exp = a["tls"], a["dns"], a["exposure"]
    lines += [
        "", "## Certificado TLS", "",
        md(tls["error"]) if tls.get("error") else
        f"Emisor: {md(tls.get('issuer'))} · caduca: {md(tls.get('not_after'))} ({md(tls.get('days_left'))} días) · {md(tls.get('tls_version'))}",
        "", "## Correo", "",
        f"SPF: {'sí (' + md(dns.get('spf_all')) + ')' if dns.get('spf_found') else 'no'} · "
        f"DMARC: {'sí (p=' + md(dns.get('dmarc_policy')) + ')' if dns.get('dmarc_found') else 'no'}",
        "", "## Servicios expuestos (Shodan InternetDB)", "",
        md(exp["error"]) if exp.get("error") else f"Puertos: {md(', '.join(map(str, exp.get('open_ports', []))) or 'ninguno')}",
        "", "## Subdominios", "",
        md(a["subdomains"]["error"]) if a["subdomains"].get("error") else f"{a['subdomains'].get('total', 0)} encontrados en crt.sh.",
        "",
    ]
    return "\n".join(lines)
