# Alcance: qué venía de la Práctica 1 y qué es nuevo en la Práctica 3

Este documento evita que la memoria haga parecer que todo estaba implementado en la Práctica 1. Las fuentes son la memoria de la Práctica 1 (25/05/2026), su *road map* (apartado 8) y el código de GitHub en el commit `1c53270`, el último antes de la Práctica 3.

Leyenda de columnas:

- **Original P1:** implementado y entregado en la Práctica 1.
- **Roadmap P1:** prometido en la Práctica 1 como mejora futura, sin implementar.
- **Mejora P3:** implementado en la Práctica 3.
- **Cambio de alcance:** diferencia entre lo que se prometió y lo que se ha hecho.

## 1. Capacidades

| Capacidad | Original P1 | Roadmap P1 | Mejora P3 | Cambio de alcance |
|---|---|---|---|---|
| Conectividad HTTP/HTTPS y redirección | Sí | — | Redirecciones validadas una a una (anti-SSRF) | Ninguno |
| 6 cabeceras de seguridad | Sí | — | Sin cambios funcionales; reutiliza la petición HTTPS | Ninguno |
| DNS (A, AAAA, MX, NS, TXT) | Sí | — | Corrección: los TXT fragmentados se concatenan sin espacio (RFC 7208) | Ninguno |
| SPF / DMARC | Sí (solo presencia) | — | Calificador SPF (`-all`/`~all`/`+all`) y política DMARC (`p=`) | Ampliación |
| Puntuación global | Sí (50 HTTPS + 50 cabeceras) | — | Modelo v2 de 4 áreas + penalización | **Modificado** (ver apartado 2) |
| Recomendaciones | Sí (solo cabeceras) | — | Todas las áreas, ordenadas por severidad | Ampliación |
| Dashboard | Sí | — | Pestañas de detalle y desglose de puntos | Ampliación |
| Informe HTML | Sí, **con inyección HTML** | — | Escapado completo + CSP | Corrección de seguridad |
| Validación del dominio | **No.** La memoria lo afirmaba, pero `validate_domain()` no se llamaba | «Validar también en el servidor» | Validación + anti-SSRF | Corrección |
| Certificado TLS | No | Sí | Sí | Ninguno |
| Puertos expuestos | No (el README P1 prometía «puertos comunes» en `scanner.py`) | «Integración con Shodan (API)» | Shodan **InternetDB** (gratuita, sin clave, pasiva) | Cambio de fuente: InternetDB en vez de la API de pago de Shodan; **no** hay escaneo de puertos propio |
| CVE asociadas | No | No | Sí (las devuelve InternetDB) | **Nuevo**, no estaba previsto |
| Subdominios (crt.sh) | No | Sí | Sí | Ninguno |
| Detección de tecnologías | No (marcado como «pendiente» en `scanner.py`) | Implícito (README P1) | Sí, por cabeceras y cookies | Ninguno |
| Resumen con IA | **No.** En P1 `ai_report.py` generaba el HTML sin IA, pese al nombre «CyberScope AI» | Sí (API de Claude) | Sí, con alternativa por reglas | Ninguno. El modo Claude **no está validado** (sin clave) |
| Historial (SQLite) | No | Sí | Sí, con gráfica de evolución | Ninguno |
| Login | No (acceso abierto) | «Autenticación básica» | Sí | Ampliación |
| Roles admin / analyst | No | No | Sí | **Nuevo** |
| Rate limiting | No | Sí (por IP) | Sí, **por usuario** | Cambio: por usuario, porque detrás de un proxy la IP no es fiable |
| Auditoría | No | No | Sí | **Nuevo** (para RNF-05) |
| Docker | No | Sí | Dockerfile + compose | Ninguno. **No validado** en este entorno |
| Caddy (proxy HTTPS) | No | «HTTPS con Let's Encrypt» | Caddyfile | Implementado con Caddy. **No validado**; sin dominio no hay HTTPS |
| Exportación PDF | No | Sí (WeasyPrint) | HTML imprimible a PDF | **Modificado** (RF-14) |
| Exportación Markdown | No | No | Sí | **Nuevo** (sustituye al PDF) |
| Exportación JSON | Solo visor JSON en pantalla | No | Descarga de JSON | **Nuevo** (la descarga) |
| Ejecución en paralelo + caché | No | Sí | Sí | Ninguno |
| VirusTotal / HIBP | No | Sí | No | **Descartado** (RF-18) |

## 2. Cambio de la puntuación global (RF-06)

**Clasificación: requisito modificado.** No es solo una decisión técnica interna.

- El enunciado del requisito («puntuación 0-100 con nivel de riesgo Bajo/Medio/Alto») se mantiene, y los umbrales no cambian.
- Pero la memoria de la Práctica 1 fijó la fórmula como parte de su especificación (fase 4: «modelo de dos mitades»), y el cambio altera el resultado que ve el usuario para el mismo dominio.
- Por eso se trata como modificación de requisito, con justificación, para no ocultar el cambio.

| | Práctica 1 (original) | Práctica 3 (nueva) |
|---|---|---|
| HTTPS | 50 pts: −30 sin HTTPS, −10 sin redirección, −40 si hay error de conexión | 25 pts: 15 si responde por HTTPS, +10 si redirige; 0 si hay error |
| Cabeceras | 50 pts (puntuación de cabeceras / 2) | 30 pts (puntuación de cabeceras × 0,3) |
| Certificado TLS | — | 20 pts: 10 si es confiable, +5 si usa TLS ≥ 1.2, +5 si no caduca en < 30 días |
| Correo | — | 25 pts: SPF 12 (`-all`/`~all`) o 6 (otro), DMARC 13 (`reject`), 11 (`quarantine`) o 5 (`none`/sin política) |
| Exposición | — | −5 por puerto peligroso, máx. −15 |
| Niveles | 80-100 Bajo · 50-79 Medio · 0-49 Alto | **Sin cambios** |

**Razón.**
- En la Práctica 1, un dominio sin SPF ni DMARC, o con el certificado caducado, podía obtener 100/100. Era contradictorio con los avisos del propio dashboard.
- Además, un dominio inaccesible sacaba 10/50 en HTTPS en vez de 0.

**Consecuencias.**
- Las puntuaciones de la Práctica 1 y de la Práctica 3 **no son comparables**. Por ejemplo, la figura 2 de la memoria P1 muestra `evolucionar.es` con 75/100; con el modelo nuevo saldría otra cifra.
- El historial solo contiene puntuaciones del modelo v2.
- Hay una incoherencia menor detectada en la auditoría y **no corregida** (*feature freeze*): un SPF terminado en `+all` recibe 6 de 12 puntos aunque la recomendación lo marque como severidad Alta. Se recoge en `limitaciones.md`.

**Trazabilidad:** RF-06, implementado en `modules/scoring.py` y probado con PR-19 y PR-20.
