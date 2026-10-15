# Matriz de trazabilidad

Relaciona cada requisito con su implementación, sus pruebas y su evidencia.

- Las pruebas **PR-xx** son automáticas (`tests/`). Las **M-xx** son manuales y están documentadas en `plan_de_pruebas.md`.
- La columna **Vídeo** se completa al grabar, con el minuto exacto en que se demuestra cada requisito.

| Requisito | Descripción | Estado final | Implementación | Prueba | Evidencia |
|---|---|---|---|---|---|
| RF-01 | Entrada, limpieza y validación del dominio | Cumplido | `modules/utils.py` (`sanitize_domain`, `validate_domain`, `check_target`), `app.py` (`start_analysis`) | PR-01, PR-02, PR-05, M-02 | Vídeo __:__ |
| RF-02 | Conectividad HTTP/HTTPS y redirección | Cumplido | `modules/scanner.py`, `modules/http_client.py` | PR-06, M-01 | Vídeo __:__ |
| RF-03 | 6 cabeceras de seguridad con puntuación | Cumplido | `modules/headers.py` | PR-10, PR-11, M-01 | Vídeo __:__ |
| RF-04 | Registros DNS A/AAAA/MX/NS/TXT | Cumplido | `modules/dns_analyzer.py` | M-01 | Vídeo __:__ |
| RF-05 | SPF y DMARC (con calificador y política) | Cumplido (ampliado) | `modules/dns_analyzer.py` | PR-13, PR-14, M-01 | Vídeo __:__ |
| RF-06 | Puntuación global y nivel de riesgo | Modificado: modelo v2 de 4 áreas | `modules/scoring.py` | PR-19, PR-20 | Memoria apdo. 4 · Vídeo __:__ |
| RF-07 | Recomendaciones concretas y priorizadas | Cumplido (ampliado) | `modules/scoring.py` (`build_recommendations`) | PR-11, PR-21 | Vídeo __:__ |
| RF-08 | Dashboard web | Cumplido | `app.py` (`render_results`) | M-01 | Vídeo __:__ |
| RF-09 | Informe HTML descargable | Cumplido (corregida inyección HTML) | `modules/report.py` | PR-22, M-04 | Vídeo __:__ |
| RF-10 | Certificado TLS | Cumplido | `modules/tls_analyzer.py` | PR-15, M-01 | Vídeo __:__ |
| RF-11 | Servicios expuestos (Shodan InternetDB) | Cumplido | `modules/exposure.py` | PR-16, PR-17, M-01 | Vídeo __:__ |
| RF-12 | Resumen ejecutivo con IA | Cumplido (con alternativa por reglas) | `modules/ai_report.py` | PR-24, PR-25, PR-26, PR-27, M-05 | Vídeo __:__ |
| RF-13 | Subdominios (crt.sh) | Cumplido | `modules/subdomains.py` | PR-18, M-01 | Vídeo __:__ |
| RF-14 | Exportación a PDF | Modificado: HTML imprimible + Markdown + JSON | `modules/report.py`, `app.py` | PR-23, M-04 | Memoria apdo. 4 · Vídeo __:__ |
| RF-15 | Historial en SQLite | Cumplido | `modules/storage.py`, `app.py` (`history_page`) | PR-35, M-06 | Vídeo __:__ |
| RF-16 | Autenticación | Cumplido (ampliado con roles) | `modules/auth.py`, `app.py` (`login_page`, `admin_page`) | PR-28 a PR-33, M-03, M-07 | Vídeo __:__ |
| RF-17 | Detección de tecnologías | Cumplido | `modules/scanner.py` (`detect_technologies`) | PR-12 | Vídeo __:__ |
| RF-18 | VirusTotal / HIBP | Descartado | — | — | Memoria apdo. 4 y 10 |
| RNF-01 | Solo reconocimiento pasivo | Cumplido | Todos los módulos; InternetDB en lugar de escaneo | Revisión de código, M-01 | Memoria apdo. 5 |
| RNF-02 | Tolerancia a errores de red | Cumplido | `http_client.py`, `exposure.py`, `subdomains.py`, `ai_report.py` | PR-07, PR-09, PR-17, PR-26, M-10 | Vídeo __:__ |
| RNF-03 | Instalación reproducible | Cumplido | `README.md`, `Dockerfile`, `docker-compose.yml`, `requirements.txt` | M-08 | Vídeo __:__ |
| RNF-04 | Análisis en 5-15 s | Cumplido | `modules/analysis.py` (paralelo + caché de 10 min) | M-01 (medido) | Memoria apdo. 8 |
| RNF-05 | Uso ético y auditoría | Cumplido | `app.py` (confirmación), `modules/storage.py` (auditoría + retención) | PR-37, M-02 | Vídeo __:__ |
| RNF-06 | Límite de uso | Cumplido | `modules/auth.py` (`rate_limit_status`) | PR-34, M-09 | Vídeo __:__ |
| RNF-07 | Validación en servidor / anti-SSRF | Cumplido | `modules/utils.py`, `modules/http_client.py` | PR-03, PR-04, PR-08, M-02 | Vídeo __:__ |
| RNF-08 | HTTPS en el servidor | Parcial (falta dominio) | `deploy/Caddyfile`, `docker-compose.yml` | M-08 | Memoria apdo. 4 |
| RNF-09 | Seguridad del propio producto | Cumplido | `report.py` (escapado + CSP), `storage.py` (SQL parametrizado), `.gitignore`, CI | PR-22, PR-25, PR-36, `pip-audit` | `docs/evidencias/` |
