# Requisitos de CyberScope AI

La memoria de la Práctica 1 (25/05/2026) no numeraba los requisitos. Se han extraído de sus apartados 1, 2, 3, 5, 6 y 8 y se han numerado para la Práctica 3. Las mejoras que la Práctica 1 planificó en su *road map* (apartado 8) se incorporan como RF-10 en adelante y RNF-06 en adelante.

## 1. Clasificación inicial (revisión al empezar la Práctica 3)

Estado según el enunciado: **Cumplido**, **Parcial**, **Pendiente**, **A revisar** o **Descartado**.

| ID | Requisito | Origen (memoria P1) | Estado inicial | Observación de la revisión |
|---|---|---|---|---|
| RF-01 | Introducir un dominio, validarlo y limpiarlo | §3.3, §6.2 | Parcial | `validate_domain()` existía pero no se llamaba; la limpieza solo quitaba `http(s)://` |
| RF-02 | Comprobar HTTP/HTTPS, estado y redirección a HTTPS | §3.2, fase 2 | Cumplido | — |
| RF-03 | Analizar las 6 cabeceras de seguridad con puntuación parcial | §3.2, fase 3 | Cumplido | — |
| RF-04 | Consultar registros DNS A, AAAA, MX, NS y TXT | §3.2, fase 7 | Cumplido | Los TXT fragmentados se unían con espacio (incorrecto según RFC 7208) |
| RF-05 | Detectar SPF y DMARC | §3.2, fase 7 | Cumplido | Solo se detectaba presencia, no la política |
| RF-06 | Puntuación global 0-100 y nivel de riesgo | fase 4 | A revisar | DNS/SPF/DMARC se analizaban pero no puntuaban |
| RF-07 | Recomendaciones concretas | §6.3 | Parcial | Solo para cabeceras |
| RF-08 | Dashboard web con los resultados | fase 5 | Cumplido | — |
| RF-09 | Informe HTML descargable | fase 6, §6.4 | Parcial | Insertaba datos externos sin escapar (inyección HTML) |
| RF-10 | Análisis del certificado TLS | road map | Pendiente | — |
| RF-11 | Puertos/servicios expuestos vía Shodan, sin escaneo activo | road map | Pendiente | — |
| RF-12 | Resumen con IA generativa (API de Claude) | road map | Pendiente | — |
| RF-13 | Descubrimiento de subdominios (crt.sh) | road map | Pendiente | — |
| RF-14 | Exportación del informe a PDF | road map | Pendiente | — |
| RF-15 | Historial de análisis en SQLite | road map | Pendiente | — |
| RF-16 | Autenticación básica | road map | Pendiente | — |
| RF-17 | Detección de tecnologías expuestas | README P1 (módulos en desarrollo) | Pendiente | — |
| RF-18 | Integración con VirusTotal y Have I Been Pwned | road map | Pendiente | — |
| RNF-01 | Solo reconocimiento pasivo | §2.2 | Cumplido | — |
| RNF-02 | Tolerar errores de red y timeouts sin romperse | §7.2 | Cumplido | — |
| RNF-03 | Despliegue reproducible siguiendo la guía | §5 | Parcial | Faltaba `dnspython` en `requirements.txt` del repositorio; la app corría como root con `nohup` |
| RNF-04 | Tiempo de análisis de 5 a 15 s | §6.2 | Parcial | Módulos en secuencia; sin caché |
| RNF-05 | Uso ético solo sobre dominios autorizados | §2.2 | Pendiente | Solo era un aviso de texto |
| RNF-06 | Rate limiting contra uso abusivo | road map | Pendiente | — |
| RNF-07 | Validación del dominio en el servidor | road map | Pendiente | Además, la app era vulnerable a SSRF |
| RNF-08 | HTTPS en el servidor (Let's Encrypt) | road map | Pendiente | La app se sirve por HTTP en el puerto 80 |
| RNF-09 | Seguridad del propio producto (sin secretos, sin XSS/SQLi, dependencias revisadas) | Enunciado P3 §5 | Pendiente | Requisito transversal del enunciado |

## 2. Requisitos modificados o descartados

### RF-06 · Puntuación global (A revisar → modificado)

Se clasifica como **requisito modificado** y no como simple decisión técnica, porque la memoria P1 fijó la fórmula 50/50 y el cambio altera el resultado visible. El análisis completo está en [`alcance.md`](alcance.md) §2.

- **Versión original:** 50 puntos HTTPS (−30 sin HTTPS, −10 sin redirección, −40 si hay error) + 50 puntos cabeceras. Umbrales: 80-100 Bajo, 50-79 Medio, 0-49 Alto.
- **Problema:** un dominio sin SPF ni DMARC, o con el certificado caducado, podía sacar 100/100. La puntuación contradecía las advertencias del propio dashboard.
- **Versión nueva:** HTTPS 25 + cabeceras 30 + TLS 20 + correo 25, con una penalización de hasta −15 por servicios peligrosos expuestos. Los umbrales de riesgo no cambian (80/50).
- **Consecuencia:** las puntuaciones de la Práctica 1 no son comparables con las nuevas. Por ejemplo, `evolucionar.es` sacaba 75 en P1. Se documenta en la memoria.

### RF-14 · Exportación a PDF (modificado)

- **Versión original:** descargar el informe en PDF con WeasyPrint.
- **Problema:** WeasyPrint necesita librerías del sistema (Pango/GTK) que complican la instalación en Windows y la imagen Docker. Esto choca con RNF-03.
- **Versión nueva:** el informe HTML incluye estilos de impresión y se guarda en PDF con *Imprimir → Guardar como PDF*. Se añaden además las exportaciones a **Markdown** y **JSON**.
- **Consecuencia:** el PDF necesita un paso manual del usuario.

### RF-16 · Autenticación básica (ampliado)

- **Versión original:** *login* simple.
- **Versión nueva:** *login* con roles `admin`/`analyst`, bloqueo tras 5 fallos, caducidad de sesión, historial separado por usuario y panel de administración.

### RF-18 · VirusTotal y Have I Been Pwned (descartado)

- **Motivo:**
  - La API pública de VirusTotal limita a 4 peticiones por minuto y sus condiciones prohíben el uso en productos o servicios.
  - La búsqueda por dominio de HIBP exige verificar la propiedad del dominio y una suscripción de pago.
  - Ninguna de las dos se puede demostrar de forma honesta en la entrega.
- **Consecuencia:** queda como trabajo futuro (memoria, apartado 10).

### RNF-08 · HTTPS en el servidor (parcial)

- **Implementado:** Caddy hace de proxy y obtiene el certificado de Let's Encrypt automáticamente cuando `SITE_ADDRESS` es un dominio. También añade las cabeceras de seguridad.
- **Limitación:** el servidor actual de Hetzner solo tiene IP pública, sin dominio, así que allí se sirve por HTTP. Con un dominio apuntando a la IP, el Caddyfile debería obtener el certificado, pero **no está validado** (Docker no probado).
