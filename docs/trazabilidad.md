# Matriz de trazabilidad

Relaciona cada requisito con su implementación, sus pruebas y su evidencia.

- **PR-xx:** prueba automática en `tests/` (resultado en `docs/evidencias/pytest.txt`).
- **M-xx:** prueba manual de `plan_de_pruebas.md`.
- **Vídeo:** se completará con el minuto exacto **después** de grabar. Ningún minuto está inventado: mientras no haya vídeo, figura como *pendiente*.

Estado de las pruebas manuales a 15/10/2026:

- **Superadas:** M-01, M-02, M-03, M-06, M-11, M-12.
- **Pendientes:** M-04, M-05, M-07, M-09, M-10.
- **No validable en este entorno:** M-08 (Docker).

| Requisito | Descripción | Estado final | Implementación real | Prueba real | Evidencia |
|---|---|---|---|---|---|
| RF-01 | Entrada, limpieza y validación del dominio | Cumplido | `modules/utils.py` (`sanitize_domain`, `validate_domain`, `check_target`); `app.py` (`start_analysis`) | PR-01, PR-02, PR-05; M-02 ✅ | pytest; M-02 (navegador, 15/10). Vídeo: pendiente |
| RF-02 | Conectividad HTTP/HTTPS y redirección | Cumplido | `modules/scanner.py` (`scan_domain`); `modules/http_client.py` (`safe_get`) | PR-06; M-01 ✅ | pytest; M-01: `example.org` → HTTP 200, HTTPS 200, sin redirección. Vídeo: pendiente |
| RF-03 | 6 cabeceras de seguridad con puntuación | Cumplido | `modules/headers.py` | PR-10, PR-11; M-01 ✅ | pytest; M-01: 0/6 en `example.org`. Vídeo: pendiente |
| RF-04 | Registros DNS A/AAAA/MX/NS/TXT | Cumplido | `modules/dns_analyzer.py` (`analyze_dns`, `_query`, `_format_record`) | **Sin prueba automática** (consulta DNS real); M-01 ✅ | M-01: A, AAAA, MX, NS y TXT reales de `example.org` (`plan_de_pruebas.md`). Vídeo: pendiente |
| RF-05 | SPF y DMARC (calificador y política) | Cumplido (ampliado) | `modules/dns_analyzer.py` (`parse_spf_all`, `parse_dmarc_policy`) | PR-13, PR-14; M-01 ✅ | pytest; M-01: SPF `-all`, DMARC `reject`. Vídeo: pendiente |
| RF-06 | Puntuación global y nivel de riesgo | **Modificado** (ver `alcance.md` §2) | `modules/scoring.py` (`calculate_global_score`) | PR-19, PR-20; M-01 ✅ | pytest; M-01: 60/100 Medio. `alcance.md` §2. Vídeo: pendiente |
| RF-07 | Recomendaciones priorizadas | Cumplido (ampliado) | `modules/scoring.py` (`build_recommendations`); `modules/headers.py` | PR-11, PR-21; M-01 ✅ | pytest; M-01: 7 recomendaciones. Vídeo: pendiente |
| RF-08 | Dashboard web | Cumplido | `app.py` (`render_results`) | M-01 ✅ | M-01 (navegador). Vídeo: pendiente |
| RF-09 | Informe HTML descargable | Cumplido (corregida inyección HTML) | `modules/report.py` (`generate_html_report`) | PR-22; M-04 ⏳ | pytest. Generación comprobada por script; la **descarga desde la app** está pendiente (M-04) |
| RF-10 | Certificado TLS | Cumplido | `modules/tls_analyzer.py` | PR-15; M-01 ✅ | pytest; M-01: Cloudflare, 71 días, TLS 1.3. Vídeo: pendiente |
| RF-11 | Puertos y CVE (Shodan InternetDB) | Cumplido | `modules/exposure.py` | PR-16, PR-17; M-01 ✅ | pytest; M-01: 13 puertos observados. Vídeo: pendiente |
| RF-12 | Resumen ejecutivo con IA | Cumplido **en modo reglas**; modo Claude **NO VALIDADO** | `modules/ai_report.py` | PR-24, PR-25, PR-26, PR-27 (API simulada); M-01 ✅ (reglas); M-05 ⏳ (Claude) | Reglas: M-01, aviso visible en la interfaz. Claude: pendiente, sin clave de API |
| RF-13 | Subdominios (crt.sh) | Cumplido | `modules/subdomains.py` | PR-18; M-01 ✅ | pytest; M-01: 2 subdominios. Vídeo: pendiente |
| RF-14 | Exportación a PDF | **Modificado:** HTML imprimible + Markdown + JSON | `modules/report.py`; `app.py` (botones de descarga) | PR-23; M-04 ⏳ | pytest. Descargas desde la app: pendiente (M-04) |
| RF-15 | Historial en SQLite | Cumplido | `modules/storage.py`; `app.py` (`history_page`) | PR-35; M-06 ✅ | pytest; M-06 (navegador). Vídeo: pendiente |
| RF-16 | Autenticación (ampliada con roles) | Cumplido | `modules/auth.py`; `app.py` (`login_page`, `admin_page`) | PR-28 a PR-33; M-03 ✅; M-07 ⏳ | pytest; M-03 y M-11 (credenciales del README). Rol analista en navegador: pendiente (M-07) |
| RF-17 | Detección de tecnologías | Cumplido | `modules/scanner.py` (`detect_technologies`); `app.py` (`plain_field`) | PR-12; M-01 ✅; M-12 ✅ | pytest; M-01: «Server: cloudflare». Vídeo: pendiente |
| RF-18 | VirusTotal / HIBP | **Descartado** | — | — | `requisitos.md` §2 |
| RNF-01 | Solo reconocimiento pasivo (no intrusivo) | Cumplido, con matiz (ver `plan_de_pruebas.md` §5) | Todos los módulos; InternetDB en vez de escaneo | Revisión de código (auditoría pre-push) | `plan_de_pruebas.md` §5 |
| RNF-02 | Tolerancia a errores | Cumplido | `http_client.py`, `exposure.py`, `subdomains.py`, `ai_report.py`, `app.py` | PR-07, PR-09, PR-17, PR-26, **PR-38**; M-10 ⏳ | pytest. PR-38 corrige un fallo real hallado en la auditoría |
| RNF-03 | Instalación reproducible | Cumplido (**ruta Python**). Docker **NO VALIDADO** | `README.md`, `requirements.txt`, `.env.example`; `Dockerfile`, `docker-compose.yml` | M-11 ✅ (Python); M-08 ⏳ (Docker) | M-11: instalación limpia, *health* `ok`, login con credenciales del README |
| RNF-04 | Análisis en 5-15 s | Cumplido | `modules/analysis.py` (ThreadPoolExecutor + caché) | M-01 ✅ (medido) | M-01: 6,5 s (consola, primera ejecución) |
| RNF-05 | Uso ético y auditoría | Cumplido | `app.py` (casilla de autorización); `modules/storage.py` (`audit`, `purge_old_records`) | PR-37; M-02 ✅ | M-02: evento `analysis_rejected` en la auditoría |
| RNF-06 | Límite de uso | Cumplido | `modules/auth.py` (`rate_limit_status`); `app.py` | PR-34; M-09 ⏳ | pytest. En la app: pendiente (M-09) |
| RNF-07 | Validación en servidor / anti-SSRF | Cumplido | `modules/utils.py` (`check_target`, `is_public_ip`); `modules/http_client.py` | PR-03, PR-04, PR-08; M-02 ✅ | pytest; M-02 (`localhost` rechazado) |
| RNF-08 | HTTPS en el servidor | **Parcial / NO VALIDADO** | `deploy/Caddyfile`, `docker-compose.yml` | M-08 ⏳ | Hetzner sigue por HTTP (sin dominio). `limitaciones.md` §2 |
| RNF-09 | Seguridad del propio producto | Cumplido, con riesgos residuales documentados | `report.py` (escapado + CSP); `app.py` (`plain_field`); `storage.py` (SQL parametrizado); `.gitignore`; CI | PR-22, PR-25, PR-36; M-12 ✅; `pip-audit`; `gitleaks` | `docs/evidencias/` (pytest, pip-audit, gitleaks) |
