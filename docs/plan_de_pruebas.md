# Plan de pruebas

## 1. Estrategia

| Tipo | Herramienta | Alcance |
|---|---|---|
| Automáticas unitarias y de integración | `pytest` (69 casos, PR-01 a PR-37) | Validación, anti-SSRF, módulos de análisis con respuestas simuladas, puntuación, informes, IA, autenticación, historial y auditoría. No usan la red, así que el resultado es reproducible |
| Manuales de extremo a extremo | Navegador + app real | Flujos completos sobre dominios de prueba (`example.org`, reservado por la IANA) y sobre el objetivo de laboratorio |
| Seguridad de dependencias | `pip-audit`, Dependabot | Vulnerabilidades conocidas en `requirements.txt` |
| Integración continua | GitHub Actions (`.github/workflows/ci.yml`) | `pytest` + `pip-audit` en cada *push* |

**Ética:** todas las pruebas se hacen sobre `example.org` (dominio de documentación de la IANA), sobre el objetivo de laboratorio (`lab-target`) o sobre infraestructura propia. Nunca sobre sistemas de terceros.

Ejecución:

```bash
pip install -r requirements-dev.txt
pytest -v
pip-audit -r requirements.txt
```

## 2. Pruebas automáticas

| ID | Requisito | Qué verifica | Estado |
|---|---|---|---|
| PR-01 | RF-01 | Limpieza de la entrada: esquema, ruta, credenciales, puerto, mayúsculas | Superada |
| PR-02 | RF-01 | Formato de dominio: rechaza IPs, `localhost`, inyección de comandos y etiquetas >63 caracteres | Superada |
| PR-03 | RNF-07 | Clasificación de IPs públicas e internas (incluidas metadatos de la nube e IPv4 encapsulada en IPv6) | Superada |
| PR-04 | RNF-07 | Un dominio que resuelve a una IP interna se rechaza, aunque sea solo una de sus IPs | Superada |
| PR-05 | RF-01 | Dominio válido aceptado; sin DNS rechazado; host de laboratorio permitido solo si se declara | Superada |
| PR-06 | RF-02 | Detección de HTTPS y de la redirección HTTP → HTTPS | Superada |
| PR-07 | RNF-02 | Un *timeout* devuelve un error legible, sin excepción | Superada |
| PR-08 | RNF-07 | Una redirección hacia `127.0.0.1` se bloquea | Superada |
| PR-09 | RNF-02 | Un bucle de redirecciones se corta tras 5 saltos | Superada |
| PR-10 | RF-03 | 6/6 cabeceras = 100 puntos y ninguna recomendación | Superada |
| PR-11 | RF-03, RF-07 | Cada cabecera ausente genera su recomendación; tabla de puntos | Superada |
| PR-12 | RF-17 | Detección de tecnologías y de versiones expuestas | Superada |
| PR-13 | RF-05 | Política DMARC (`p=`), ignorando `sp=` y valores inválidos | Superada |
| PR-14 | RF-05 | Calificador SPF (`-all`, `~all`, `+all`) | Superada |
| PR-15 | RF-10 | Emisor, fechas, días restantes y aviso de caducidad del certificado | Superada |
| PR-16 | RF-11 | Puertos peligrosos y filtrado de datos inválidos de InternetDB | Superada |
| PR-17 | RNF-02 | InternetDB caído: el análisis continúa con aviso | Superada |
| PR-18 | RF-13 | Subdominios únicos, sin comodines ni dominios ajenos ni HTML | Superada |
| PR-19 | RF-06 | Configuración perfecta = 100 (Bajo); sin conexión = 0 (Alto) | Superada |
| PR-20 | RF-06 | Pesos por área y penalización máxima de −15 | Superada |
| PR-21 | RF-07 | Recomendaciones de todas las áreas, ordenadas por severidad | Superada |
| PR-22 | RF-09, RNF-09 | Una carga XSS en cabeceras/DNS/TLS/subdominios queda escapada en el informe; hay CSP | Superada |
| PR-23 | RF-14 | Informe Markdown completo y sin HTML activo | Superada |
| PR-24 | RF-12 | Sin clave de API: resumen por reglas, indicado de forma explícita | Superada |
| PR-25 | RF-12, RNF-09 | Texto de *prompt injection* en TXT/cabeceras no llega al modelo | Superada |
| PR-26 | RF-12, RNF-02 | Fallo de la API de Claude: alternativa por reglas con aviso | Superada |
| PR-27 | RF-12 | Con clave: se devuelve el texto y el modelo usado | Superada |
| PR-28 | RF-16 | PBKDF2 con sal: hashes distintos y sin la contraseña en claro | Superada |
| PR-29 | RF-16 | Política de contraseñas (12+ caracteres, letras y números) | Superada |
| PR-30 | RF-16 | *Login* correcto devuelve el rol; mismo error para usuario inexistente y clave errónea | Superada |
| PR-31 | RF-16 | Bloqueo tras 5 fallos (incluso con la clave correcta) y registro en auditoría | Superada |
| PR-32 | RF-16 | Un usuario desactivado no puede entrar | Superada |
| PR-33 | RF-16 | El administrador inicial se crea desde `.env` una sola vez | Superada |
| PR-34 | RNF-06 | Límite de análisis por usuario y ventana | Superada |
| PR-35 | RF-15 | Historial guardado; un analista no puede abrir análisis de otro | Superada |
| PR-36 | RNF-09 | Intentos de inyección SQL sin efecto | Superada |
| PR-37 | RNF-05 | Purga de auditoría pasada la retención | Superada |

Resultado de la ejecución del 15/10/2026: **69 pasadas, 0 fallidas**, en 4,1 s. Hay 69 casos para 37 identificadores porque algunas pruebas tienen varios casos parametrizados.

## 3. Pruebas manuales de extremo a extremo

| ID | Requisito | Pasos | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|---|
| M-01 | RF-02 a RF-13, RNF-04 | *Login* como admin → analizar `example.org` con la autorización marcada | Dashboard completo, puntuación, pestañas con datos reales, en <15 s | 60/100 (Medio). HTTPS 200 sin redirección, 0/6 cabeceras, certificado de Cloudflare válido (71 días, TLS 1.3), SPF `-all` y DMARC `reject`, 13 puertos (CDN), 2 subdominios. Tiempo: 6,5 s (primera ejecución) | Superada |
| M-02 | RF-01, RNF-05, RNF-07 | a) Analizar sin marcar la autorización. b) Analizar `http://localhost:8501` | a) Aviso y no se analiza. b) Rechazo sin llegar a conectarse; queda en la auditoría | a) «Debes confirmar que tienes autorización…». b) «Formato de dominio no válido…», con evento `analysis_rejected` en la auditoría | Superada |
| M-03 | RF-16 | *Login* con clave errónea y después con la correcta | Mensaje genérico y luego acceso con el rol | «Usuario o contraseña incorrectos.» y luego acceso como administrador | Superada |
| M-04 | RF-09, RF-14 | Descargar los informes HTML, Markdown y JSON y abrirlos | Ficheros completos; HTML sin recursos externos e imprimible a PDF | *Pendiente de registrar en el vídeo* | Pendiente |
| M-05 | RF-12 | Con `ANTHROPIC_API_KEY` válida, analizar un dominio | Resumen generado con IA y modelo indicado | *Pendiente: requiere clave de API* | Pendiente |
| M-06 | RF-15 | Abrir Historial tras varios análisis | Gráfica de evolución y reapertura de un análisis | Historial con el análisis #1 de `example.org`, reabierto correctamente | Superada |
| M-07 | RF-16 | Crear un analista desde Administración y entrar con él | No ve Administración; solo ve su historial | *Pendiente de registrar en el vídeo* | Pendiente |
| M-08 | RNF-03, RNF-08 | Instalación desde cero con `docker compose up -d --build` en una máquina limpia | App accesible en `http://localhost` con las cabeceras de seguridad de Caddy | *Pendiente: Docker no disponible en el equipo de desarrollo* | Pendiente |
| M-09 | RNF-06 | Lanzar 11 análisis en 10 min con el mismo usuario | El análisis 11 se deniega y se registra | *Pendiente de registrar en el vídeo* (cubierto por PR-34) | Pendiente |
| M-10 | RNF-02 | Analizar un dominio inexistente (`no-existe-cyberscope.org`) | Mensaje «no resuelve», sin trazas internas | *Pendiente de registrar en el vídeo* | Pendiente |

## 4. Pruebas fallidas o con observaciones

- **`example.com` inaccesible desde la red de desarrollo.** Al probar M-01, las conexiones a `example.com` se reseteaban. `curl` también fallaba, así que el problema era de la red local y no del producto. Se usó `example.org`, también reservado por la IANA. La app mostró el error de forma controlada: «No se pudo conectar…», con 25/100 porque solo puntuaba el correo. Esto sirve también como evidencia de RNF-02.
- **Traducción automática del navegador.** Chrome traducía la interfaz («IA de CyberScope», «Medios»). No es un fallo de la app, pero para el vídeo conviene desactivar la traducción.
