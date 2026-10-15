# Changelog

## [2.0.0] · Práctica 3 · octubre 2026

Producto funcional a partir del prototipo de la Práctica 1. El alcance detallado (qué es original, qué venía del *road map* y qué es nuevo) está en [`docs/alcance.md`](docs/alcance.md).

### Corregido
- `requirements.txt` no incluía `dnspython`: la instalación desde cero fallaba.
- Inyección HTML en el informe y en el dashboard: los valores del dominio analizado se insertaban sin escapar.
- La app permitía analizar `localhost`, IPs internas y metadatos de la nube (SSRF).
- `validate_domain()` existía pero no se usaba.
- Los registros TXT fragmentados se unían con espacio (RFC 7208 exige concatenación directa).
- Se habían subido ficheros `__pycache__` al repositorio.
- *(Auditoría pre-push)* Una cabecera `Location` malformada provocaba un `ValueError` no controlado que tumbaba el análisis (PR-38).
- *(Auditoría pre-push)* Valores externos (cabecera `Server`, emisor TLS, SAN, registros DNS) se mostraban con `st.write`, que interpreta Markdown: permitía inyectar imágenes (píxel de rastreo) y enlaces. Ahora se muestran como texto literal.

### Modificado
- **RF-06 · Puntuación global:** de 50 HTTPS + 50 cabeceras a HTTPS 25 + cabeceras 30 + TLS 20 + correo 25 − exposición (máx. 15). Los umbrales no cambian. Las puntuaciones no son comparables con la Práctica 1.
- **RF-14 · PDF:** se sustituye por un HTML imprimible a PDF más exportación a Markdown y JSON.
- **Rate limiting:** por usuario en lugar de por IP.
- `ai_report.py` pasa a generar el resumen con IA; el informe HTML se mueve a `report.py`.

### Añadido
- Análisis del certificado TLS.
- Puertos y CVE vía Shodan InternetDB (pasivo).
- Subdominios vía crt.sh.
- Detección de tecnologías.
- Resumen ejecutivo con la API de Claude y alternativa por reglas.
- Historial en SQLite con gráfica.
- Login con roles, bloqueo por intentos fallidos, caducidad de sesión, límite de análisis, auditoría con retención y panel de administración.
- Ejecución en paralelo y caché de 10 min.
- Dockerfile, docker-compose con Caddy y objetivo de laboratorio. **No validados** en el entorno de desarrollo.
- 70 pruebas automáticas, CI con `pytest` y `pip-audit`, y Dependabot.
- Documentación en `docs/`: requisitos, alcance, trazabilidad, plan de pruebas, modelo de amenazas y limitaciones.

### Descartado
- **RF-18:** integración con VirusTotal y Have I Been Pwned (ver `docs/requisitos.md`).

## [1.0.0] · Práctica 1 · mayo 2026

- Interfaz Streamlit.
- Análisis HTTP/HTTPS, 6 cabeceras de seguridad, DNS, SPF y DMARC.
- Puntuación 50/50.
- Informe HTML.
- Despliegue manual en Hetzner por HTTP.
