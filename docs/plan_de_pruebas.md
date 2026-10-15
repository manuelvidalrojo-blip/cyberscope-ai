# Plan de pruebas

## 1. Estrategia

| Tipo | Herramienta | Alcance |
|---|---|---|
| Automáticas unitarias | `pytest` | Funciones puras: limpieza/validación, clasificación de IPs, *parsers* (DMARC, SPF, certificado, crt.sh, InternetDB), puntuación, informes, hashing |
| Automáticas de integración | `pytest` con respuestas de red simuladas y SQLite temporal | Varios módulos juntos: `scan_domain` + `safe_get` + `check_target`; `analyze_exposure`; `generate_ai_summary`; `auth` + `storage` sobre una base de datos real temporal |
| Manuales de extremo a extremo | Navegador + app real | Flujos completos sobre `example.org` (dominio reservado por la IANA) e instalación limpia |
| Seguridad | `pip-audit`, `gitleaks`, revisión de código | Dependencias, secretos en el historial, pasividad, inyección |
| Integración continua | GitHub Actions (`.github/workflows/ci.yml`) | `pytest` + `pip-audit` en cada *push* (se activará al subir el repositorio) |

Las pruebas automáticas **no usan la red**: todas las llamadas a `requests`, `resolve_ips` e InternetDB están simuladas. No hay pruebas de extremo a extremo automatizadas; esas se cubren con las manuales.

**Ética:** todas las pruebas se hacen sobre `example.org`, sobre `localhost` (para comprobar que se rechaza) o sobre infraestructura propia. Nunca sobre sistemas de terceros.

## 2. Resultado de la última ejecución

| Dato | Valor |
|---|---|
| Fecha | 15/10/2026 (auditoría pre-push) |
| Entorno | Windows 11, Python 3.14.3, venv |
| Pruebas recogidas | **70** (38 funciones `PR-xx`; algunas parametrizadas) |
| Superadas | **70** |
| Fallidas | 0 |
| Omitidas (*skipped*) | 0 |
| Duración | ≈ 3 s |
| Evidencia | `docs/evidencias/pytest.txt` |

En los 11 commits revisados había **69** pruebas. La auditoría añadió **PR-38** como prueba de regresión de un fallo real. Se comprobó que falla con el código anterior y pasa con la corrección.

## 3. Pruebas automáticas

**Tipo:** **U** = unitaria, **I** = integración (varios módulos, red simulada o SQLite real).

| ID | Tipo | Casos | Requisito | Módulo | Qué verifica |
|---|---|---|---|---|---|
| PR-01 | U | 6 | RF-01 | `utils` | Limpieza de la entrada: esquema, ruta, credenciales, puerto, mayúsculas |
| PR-02 | U | 10 | RF-01 | `utils` | Formato de dominio: rechaza IPs, `localhost`, inyección y etiquetas >63 caracteres |
| PR-03 | U | 10 | RNF-07 | `utils` | IPs públicas frente a internas (metadatos de la nube, IPv4 en IPv6, TEST-NET) |
| PR-04 | U | 1 | RNF-07 | `utils` | Un dominio que resuelve a una IP interna se rechaza, aunque sea solo una de sus IPs |
| PR-05 | U | 1 | RF-01 | `utils` | Dominio válido aceptado; sin DNS rechazado; laboratorio solo si se declara |
| PR-06 | I | 1 | RF-02 | `scanner` + `http_client` + `utils` | HTTPS activo y redirección HTTP → HTTPS |
| PR-07 | I | 1 | RNF-02 | `scanner` + `http_client` | Un *timeout* da un error legible, sin excepción |
| PR-08 | I | 1 | RNF-07 | `http_client` + `utils` | Una redirección a `127.0.0.1` se bloquea |
| PR-09 | I | 1 | RNF-02 | `http_client` | Un bucle de redirecciones se corta tras 5 saltos |
| PR-10 | U | 1 | RF-03 | `headers` | 6/6 cabeceras = 100 puntos, sin recomendaciones |
| PR-11 | U | 1 | RF-03, RF-07 | `headers` | Recomendación por cada cabecera ausente; tabla de puntos |
| PR-12 | U | 1 | RF-17 | `scanner` | Tecnologías y versiones expuestas |
| PR-13 | U | 4 | RF-05 | `dns_analyzer` | Política DMARC `p=` (ignora `sp=` y valores inválidos) |
| PR-14 | U | 5 | RF-05 | `dns_analyzer` | Calificador SPF (`-all`, `~all`, `+all`) |
| PR-15 | U | 1 | RF-10 | `tls_analyzer` | Emisor, fechas, días restantes y aviso de caducidad |
| PR-16 | I | 1 | RF-11 | `exposure` | Puertos peligrosos; filtrado de datos inválidos de InternetDB |
| PR-17 | I | 1 | RNF-02 | `exposure` | InternetDB caído: aviso sin romper |
| PR-18 | U | 1 | RF-13 | `subdomains` | Subdominios únicos, sin comodines, ajenos ni HTML |
| PR-19 | U | 1 | RF-06 | `scoring` | Perfecto = 100 (Bajo); sin conexión = 0 (Alto) |
| PR-20 | U | 1 | RF-06 | `scoring` | Pesos por área y penalización máxima de −15 |
| PR-21 | U | 1 | RF-07 | `scoring` | Recomendaciones de todas las áreas, ordenadas por severidad |
| PR-22 | U | 1 | RF-09, RNF-09 | `report` | XSS en cabeceras/DNS/TLS/subdominios escapado; CSP presente |
| PR-23 | U | 1 | RF-14 | `report` | Markdown completo y sin HTML activo |
| PR-24 | I | 1 | RF-12 | `ai_report` | Sin clave: resumen por reglas, indicado de forma explícita |
| PR-25 | U | 1 | RF-12, RNF-09 | `ai_report` | *Prompt injection* desde TXT/cabeceras no llega al modelo |
| PR-26 | I | 1 | RF-12, RNF-02 | `ai_report` | Fallo de la API: reglas con aviso |
| PR-27 | I | 1 | RF-12 | `ai_report` | Con clave (API simulada): texto y modelo devueltos |
| PR-28 | U | 1 | RF-16 | `auth` | PBKDF2 con sal; sin la contraseña en claro |
| PR-29 | I | 3 | RF-16 | `auth` + `storage` | Política de contraseñas |
| PR-30 | I | 1 | RF-16 | `auth` + `storage` | *Login* correcto; mismo error para usuario inexistente y clave errónea |
| PR-31 | I | 1 | RF-16 | `auth` + `storage` | Bloqueo tras 5 fallos y registro en auditoría |
| PR-32 | I | 1 | RF-16 | `auth` + `storage` | Usuario desactivado no entra |
| PR-33 | I | 1 | RF-16 | `auth` + `storage` | Administrador inicial desde `.env`, una sola vez |
| PR-34 | I | 1 | RNF-06 | `auth` + `storage` | Límite de análisis por usuario y ventana |
| PR-35 | I | 1 | RF-15 | `storage` | Historial; un analista no abre análisis ajenos |
| PR-36 | I | 1 | RNF-09 | `auth` + `storage` | Inyección SQL sin efecto |
| PR-37 | I | 1 | RNF-05 | `storage` | Purga de auditoría pasada la retención |
| PR-38 | I | 1 | RNF-02 | `http_client` + `scanner` | `Location` malformada (`http://[invalido/`): error controlado, no excepción |

**Total:** 19 funciones unitarias (49 casos) y 19 de integración (21 casos), **70 casos**.

**Sin prueba automática:** las consultas DNS reales (`_query`), el *handshake* TLS real, las llamadas reales a crt.sh, InternetDB y Claude, y la interfaz Streamlit (`app.py`). Se cubren con pruebas manuales.

## 4. Pruebas manuales

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|---|
| M-01 | RF-02 a RF-13, RF-17, RNF-04 | *Login* → analizar `example.org` con la autorización marcada | Dashboard completo con datos reales, en < 15 s | 60/100 (Medio); HTTP/HTTPS 200 sin redirección; 0/6 cabeceras; certificado de Cloudflare válido (71 días, TLS 1.3); DNS: A `104.20.26.136`, `172.66.157.237`; AAAA ×2; NS `katelyn`/`mitch.ns.cloudflare.com`; MX nulo; TXT ×2; SPF `-all`; DMARC `reject`; 13 puertos (CDN); 2 subdominios; tecnologías «Server: cloudflare»; resumen **por reglas** con aviso visible. Tiempo: 6,5 s (consola, primera ejecución) | ✅ Superada |
| M-02 | RF-01, RNF-05, RNF-07 | a) Analizar sin marcar la autorización. b) Analizar `http://localhost:8501` | a) Aviso, no se analiza. b) Rechazo y registro en auditoría | a) «Debes confirmar que tienes autorización…». b) «Formato de dominio no válido…» + evento `analysis_rejected` | ✅ Superada |
| M-03 | RF-16 | *Login* con clave errónea y luego con la correcta | Mensaje genérico y luego acceso | «Usuario o contraseña incorrectos.» y acceso como admin | ✅ Superada |
| M-04 | RF-09, RF-14 | Descargar HTML, Markdown y JSON **desde la app** y abrirlos | Ficheros completos; HTML sin recursos externos e imprimible | — (generación verificada solo por script) | ⏳ **Pendiente** |
| M-05 | RF-12 | Con `ANTHROPIC_API_KEY` válida, analizar | Resumen con IA y modelo indicado | — (no hay clave) | ⏳ **Pendiente / NO VALIDADO** |
| M-06 | RF-15 | Abrir Historial tras un análisis | Lista, gráfica y reapertura | Análisis #1 de `example.org` reabierto | ✅ Superada |
| M-07 | RF-16 | Crear un analista desde Administración y entrar con él | No ve Administración; solo su historial | — | ⏳ **Pendiente** |
| M-08 | RNF-03, RNF-08 | `docker compose up -d --build` en una máquina limpia | App en `http://localhost` con cabeceras de Caddy | — (Docker no instalado) | ⛔ **NO VALIDADO EN ESTE ENTORNO** |
| M-09 | RNF-06 | 11 análisis en 10 min con el mismo usuario | El 11.º se deniega y se registra | — (cubierto por PR-34) | ⏳ **Pendiente** |
| M-10 | RNF-02 | Analizar `no-existe-cyberscope.org` | «El dominio no resuelve…», sin trazas | — | ⏳ **Pendiente** |
| M-11 | RNF-03 | Instalación limpia según el README (detalle abajo) | Instala, arranca, *health* `ok`, *login* con credenciales del README | Todo correcto (detalle abajo) | ✅ Superada |
| M-12 | RNF-09 | Página de prueba con `Server: ![pixel](…) [Pulsa aquí](…)` pintada con `st.write` y con `st.text` | `st.text` muestra texto literal | `st.write`: **renderiza imagen y enlace** (vulnerable). `st.text`: texto literal. `app.py` corregido para usar `st.text` (`plain_field`) Además, con `streamlit.testing.v1.AppTest` se renderizó `app.py` con un análisis cuyos `Server`, emisor TLS y MX son maliciosos: con el `app.py` de HEAD el contenido acaba en `st.markdown`; con el corregido aparece solo en `st.text`, sin excepciones | ✅ Superada (verificado con página de prueba y AppTest; no con un servidor malicioso real) |

### M-11 · Instalación limpia (detalle)

Ejecutada sobre un `git clone` del commit `e0ea38f` en una carpeta vacía:

| Paso | Comando ejecutado | Resultado |
|---|---|---|
| Versión de Python | `py -3.14 --version` | `Python 3.14.3` |
| Entorno | `py -3.14 -m venv .venv` | Correcto |
| Dependencias | `.venv/Scripts/python -m pip install -r requirements.txt` | Correcto; `dnspython 2.9.0` instalado |
| Configuración | `cp .env.example .env` | Correcto |
| Ejecución | `.venv/Scripts/python -m streamlit run app.py` | «Uvicorn server started on :::8501» |
| Salud | `curl http://localhost:8501/_stcore/health` | HTTP 200, cuerpo `ok` |
| *Login* | Navegador: `admin` / `CambiaEstaClave2026` | Acceso correcto; eventos `user_bootstrap` y `login_ok` en la auditoría |
| Pruebas | `.venv/Scripts/python -m pip install -r requirements-dev.txt` + `.venv/Scripts/python -m pytest` | 69 superadas (commit `e0ea38f`, antes de PR-38) |

Diferencias con el README:

- En este equipo `python` no está en el PATH (es el alias de Microsoft Store), así que se usó el lanzador `py -3.14`. El README lo indica.
- Se invocó el Python del entorno (`.venv/Scripts/python -m …`) en lugar de activarlo; es equivalente.

Observaciones:

- El primer intento de *login* se perdió porque el formulario se recargó durante la creación inicial del administrador (no quedó registrado ningún intento). El segundo funcionó.
- `streamlit run app.py` escucha en todas las interfaces.

## 5. Verificación de reconocimiento pasivo (RNF-01)

Revisión de todas las llamadas de red del código (`grep` sobre `requests.get`, `socket`, `resolver.resolve`, `getaddrinfo` y `Anthropic`):

| Destino | Llamada | Qué hace |
|---|---|---|
| **El dominio analizado** | `http_client.safe_get` | 1 GET a `http://dominio/` y 1 GET a `https://dominio/` (puertos 80 y 443). Sigue como máximo 5 redirecciones del propio sitio |
| **El dominio analizado** | `tls_analyzer.analyze_tls` | 1 *handshake* TLS al puerto 443 |
| Resolutor DNS del sistema | `utils.resolve_ips`, `dns_analyzer._query` | Consultas A, AAAA, MX, NS, TXT y `_dmarc` TXT |
| `internetdb.shodan.io` | `exposure.query_internetdb` | 1 GET por IP del dominio (máx. 4). **Fuente externa**: no se contacta con el objetivo |
| `crt.sh` | `subdomains.find_subdomains` | 1 GET de consulta. **Fuente externa**: los subdominios no se contactan |
| `api.anthropic.com` | `ai_report._claude_summary` | Solo si hay clave; envía el resumen estructurado |

**No existe** en el código:

- escaneo de puertos ni bucles sobre puertos;
- escaneo de rangos de IPs;
- *brute force* ni listas de palabras;
- *fuzzing*;
- envío de *payloads* o explotación.

El único bucle con conexiones al objetivo es el de redirecciones (máx. 5).

**Matiz para la memoria:** CyberScope no es «pasivo» en sentido estricto, porque abre tres conexiones al objetivo: las mismas que un navegador que visita la página. La descripción precisa es **reconocimiento pasivo / no intrusivo**. La Práctica 1 hacía exactamente las mismas peticiones HTTP/HTTPS. La exposición de puertos se obtiene de una fuente externa (InternetDB), no escaneando.

## 6. Fallos encontrados durante las pruebas

| Fallo | Detectado en | Estado |
|---|---|---|
| `Location` malformada → `ValueError` no controlado que tumbaba el análisis | Auditoría pre-push (revisión de código + reproducción) | **Corregido** (`http_client.py`) + PR-38 |
| Valores externos pintados con `st.write` → inyección de imágenes y enlaces Markdown | Auditoría pre-push (M-12) | **Corregido** (`app.py`, `plain_field`) |
| `example.com` inaccesible desde la red de desarrollo | M-01 | Problema de red local, no del producto; se usa `example.org`. La app mostró el error de forma controlada (evidencia de RNF-02) |
| MX nulo mostrado como `0 ` | M-01 (auditoría) | **No corregido** (cosmético, *feature freeze*); en `limitaciones.md` |
| Traducción automática de Chrome sobre la interfaz | M-01 | No es un fallo de la app; desactivarla para el vídeo |
