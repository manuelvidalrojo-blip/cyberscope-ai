# 🛡️ CyberScope AI

**CyberScope AI** es una herramienta web de ciberseguridad (línea *Blue Team*) que analiza de forma **pasiva** la exposición externa de un dominio autorizado. Reúne en un solo panel lo que normalmente exige varias herramientas: `curl`, `dig`, securityheaders.com, crt.sh, Shodan...

Para cada dominio calcula una **puntuación de 0 a 100** y genera **recomendaciones priorizadas**. Redacta además un **resumen ejecutivo**, con IA (Claude) o por reglas, y exporta un **informe** en HTML, Markdown o JSON.

> ⚠️ **Uso ético exclusivamente.** Utiliza la herramienta solo sobre dominios de tu propiedad o con autorización expresa del propietario. La aplicación exige confirmarlo y registra cada análisis en un log de auditoría.

| Versión | Entrega |
|---|---|
| v1.0 (mayo 2026) | Práctica 1: prototipo con HTTPS, cabeceras, DNS, puntuación e informe HTML |
| **v2.0 (octubre 2026)** | **Práctica 3: producto funcional (este README). Etiqueta `v1.0-practica3`. Cambios en [`CHANGELOG.md`](CHANGELOG.md)** |

---

## ✅ Estado de validación (15/10/2026)

| Elemento | Estado |
|---|---|
| Instalación y ejecución con Python (opción A) | **Validado**: instalación limpia con Python 3.14.3 en Windows 11 |
| Pruebas automáticas | **70 superadas**, 0 fallidas |
| Resumen ejecutivo por reglas (sin clave) | **Validado** |
| Resumen ejecutivo con la API de Claude | **NO VALIDADO**: no se dispuso de clave de API |
| Docker / Caddy (opción B) | **NO VALIDADO** en el entorno de desarrollo |
| HTTPS en el servidor de Hetzner | **Pendiente**: el servidor no tiene dominio; sigue la versión de la Práctica 1 por HTTP |

Detalle en [`docs/limitaciones.md`](docs/limitaciones.md). Qué datos se guardan y durante cuánto tiempo: [`docs/modelo_de_amenazas.md`](docs/modelo_de_amenazas.md) §7.

---

## ✨ Funcionalidades

| Área | Qué hace |
|---|---|
| Conectividad | Estado HTTP/HTTPS, redirección a HTTPS y tecnologías del servidor, con aviso si se revela la versión |
| Cabeceras | Comprueba las 6 cabeceras de seguridad (HSTS, CSP, X-Frame-Options...) y explica cómo añadir cada una |
| Certificado TLS | Emisor, validez, días hasta caducar, versión de TLS y cifrado |
| DNS y correo | Registros A/AAAA/MX/NS/TXT, SPF (con su calificador `-all`/`~all`/`+all`) y DMARC (con su política `p=`) |
| Exposición | Puertos y CVE conocidos según **Shodan InternetDB**, sin escanear |
| Subdominios | Subdominios públicos según **Certificate Transparency (crt.sh)** |
| Puntuación | 0-100 en cuatro áreas ponderadas, más una penalización por servicios peligrosos expuestos (modelo v2: modifica el 50/50 de la Práctica 1, ver [`docs/alcance.md`](docs/alcance.md)) |
| Resumen ejecutivo | Con la API de Claude si hay clave (no validado); si no, por reglas, indicado de forma explícita |
| Informes | HTML autocontenido (imprimible a PDF), Markdown y JSON |
| Historial | Cada análisis queda guardado en SQLite, con gráfica de evolución por dominio |
| Usuarios | Login con roles `admin` / `analyst`, bloqueo tras 5 intentos fallidos y límite de análisis por usuario |
| Auditoría | Registro de logins, análisis, rechazos y cambios de usuarios |

---

## 📋 Requisitos previos

- **Python 3.11 o superior** y `git`. **Validado con Python 3.14.3 en Windows 11**; otras versiones no se han probado.
- Conexión a Internet: los análisis consultan el dominio, crt.sh y Shodan InternetDB.
- *(Opcional)* Una clave de la API de Anthropic para el resumen con IA. Sin clave, el resumen se genera por reglas.
- *(Opcional, ruta no validada)* Docker 24+ con Docker Compose v2.

---

## 🚀 Instalación y ejecución

### Opción A · Python (ruta validada)

Son los pasos de la instalación limpia validada el 15/10/2026. Las únicas diferencias con lo ejecutado están anotadas en [`docs/plan_de_pruebas.md`](docs/plan_de_pruebas.md), prueba M-11:

```bash
git clone https://github.com/manuelvidalrojo-blip/cyberscope-ai.git
cd cyberscope-ai
python -m venv .venv          # Windows sin 'python' en el PATH: py -3.14 -m venv .venv
# Activar el entorno:
#   Windows (cmd/PowerShell):  .venv\Scripts\activate
#   Windows (Git Bash):        source .venv/Scripts/activate
#   Linux/macOS:               source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # en cmd/PowerShell: copy .env.example .env
streamlit run app.py
```

La aplicación queda en **http://localhost:8501**. Comprobación de salud: `http://localhost:8501/_stcore/health` responde `ok`.

Notas:
- `streamlit run app.py` escucha en todas las interfaces, así que es accesible desde tu red local. Para limitarlo a tu equipo: `streamlit run app.py --server.address 127.0.0.1`.
- Recomendado (no forma parte de la ruta validada): `python -m pip install --upgrade pip`. El `pip` 25.3 que trae Python 3.14.3 tiene vulnerabilidades conocidas según `pip-audit`; no afecta a la app.

### Opción B · Docker (⚠️ NO VALIDADA)

> Los ficheros `Dockerfile`, `docker-compose.yml` y `deploy/Caddyfile` se incluyen, pero **no se han podido ejecutar** en el entorno de desarrollo (Docker no instalado). Solo se han revisado de forma estática: ver [`docs/limitaciones.md`](docs/limitaciones.md).

```bash
# desde la carpeta clonada en la opción A
cp .env.example .env          # edita al menos CYBERSCOPE_ADMIN_PASSWORD
docker compose up -d --build
```

En principio, Caddy publica la app en **http://localhost**. Con `SITE_ADDRESS=tudominio.com` en `.env`, Caddy solicitaría un certificado de Let's Encrypt.

### Datos de acceso de prueba

Al arrancar por primera vez, si la base de datos está vacía, se crea el administrador definido en `.env`:

| Usuario | Contraseña (valor de `.env.example`) | Rol |
|---|---|---|
| `admin` | `CambiaEstaClave2026` | admin |

**Cambia esta contraseña antes de exponer la app a Internet.** Desde el panel **Administración** puedes crear analistas. Desde la terminal puedes usar `python scripts/manage_users.py add <usuario> --role analyst`.

---

## 🖥️ Uso básico

1. Inicia sesión.
2. En **Analizar**, escribe el dominio (si pegas una URL completa, se limpia sola).
3. Marca la casilla *«Confirmo que este dominio es mío o tengo autorización…»* y pulsa **Analizar dominio**. El análisis tarda entre 5 y 25 s.
4. Revisa la puntuación, el resumen ejecutivo, las recomendaciones y las pestañas de detalle.
5. Descarga el informe en HTML, Markdown o JSON. Para obtener un PDF, abre el HTML y elige *Imprimir → Guardar como PDF*.
6. En **Historial** puedes ver la evolución de la puntuación de cada dominio y reabrir análisis anteriores.

### Demo con objetivo de laboratorio (requiere Docker, ⚠️ no validado)

Para hacer demos sin tocar sistemas ajenos, levanta un nginx deliberadamente mal configurado:

```bash
# en .env:  LAB_HOSTS=lab-target
docker compose --profile lab up -d --build
```

Después analiza el host `lab-target`. Solo los hosts listados en `LAB_HOSTS` se pueden analizar aunque tengan IP privada.

---

## ⚙️ Configuración (`.env`)

| Variable | Por defecto | Descripción |
|---|---|---|
| `CYBERSCOPE_ADMIN_USER` / `CYBERSCOPE_ADMIN_PASSWORD` | — | Administrador inicial (solo si no hay usuarios) |
| `ANTHROPIC_API_KEY` | vacío | Clave de la API de Claude. Vacía = resumen por reglas |
| `CLAUDE_MODEL` | `claude-opus-5-5` | Modelo para el resumen |
| `RATE_LIMIT_ANALYSES` / `RATE_LIMIT_WINDOW_MIN` | 10 / 10 | Máx. análisis por usuario y ventana (min) |
| `SESSION_TIMEOUT_MIN` | 30 | Caducidad de sesión por inactividad |
| `AUDIT_RETENTION_DAYS` | 90 | Días que se conserva la auditoría (purga al arrancar la app; ver `docs/modelo_de_amenazas.md` §7) |
| `DATA_DIR` | `data` | Carpeta de la base de datos SQLite |
| `LAB_HOSTS` | vacío | Hosts de laboratorio permitidos con IP privada |
| `SITE_ADDRESS` | `:80` | Dominio para Caddy (HTTPS automático) |

---

## 🧪 Pruebas

```bash
pip install -r requirements-dev.txt
pytest -v                       # 70 pruebas automáticas; usan respuestas simuladas, sin red
pip-audit -r requirements.txt   # vulnerabilidades conocidas en dependencias
```

Cada prueba indica en su descripción el identificador `PR-xx` y el requisito que verifica. El plan completo, incluidas las pruebas manuales de extremo a extremo, está en [`docs/plan_de_pruebas.md`](docs/plan_de_pruebas.md). GitHub Actions ejecuta pruebas y `pip-audit` en cada *push*.

---

## 📁 Estructura del proyecto

```
cyberscope-ai/
├── app.py                    # Interfaz Streamlit: login, análisis, historial, administración
├── modules/
│   ├── analysis.py           # Orquestador: valida el objetivo y ejecuta los módulos en paralelo
│   ├── utils.py              # Limpieza/validación de dominios, anti-SSRF, escapado HTML
│   ├── http_client.py        # GET seguro: redirecciones validadas y tamaño limitado
│   ├── scanner.py            # Conectividad HTTP/HTTPS y detección de tecnologías
│   ├── headers.py            # Cabeceras de seguridad
│   ├── tls_analyzer.py       # Certificado TLS
│   ├── dns_analyzer.py       # DNS, SPF y DMARC
│   ├── exposure.py           # Shodan InternetDB (puertos y CVE, pasivo)
│   ├── subdomains.py         # crt.sh (Certificate Transparency)
│   ├── scoring.py            # Puntuación global y recomendaciones
│   ├── ai_report.py          # Resumen ejecutivo (Claude o reglas)
│   ├── report.py             # Informes HTML y Markdown
│   ├── auth.py               # Usuarios, contraseñas, bloqueo y límite de uso
│   └── storage.py            # SQLite: historial, auditoría, retención
├── scripts/manage_users.py   # Gestión de usuarios por terminal
├── tests/                    # Pruebas automáticas (pytest)
├── docs/                     # Requisitos, alcance, trazabilidad, pruebas, amenazas, limitaciones
├── deploy/                   # Caddyfile y objetivo de laboratorio
├── Dockerfile · docker-compose.yml
├── .env.example              # Variables necesarias con valores ficticios
├── requirements.txt          # Dependencias fijadas
└── requirements-dev.txt      # + pytest y pip-audit
```

---

## 🔐 Seguridad

Resumen de los controles. El detalle está en [`docs/modelo_de_amenazas.md`](docs/modelo_de_amenazas.md) y las limitaciones en [`docs/limitaciones.md`](docs/limitaciones.md).

- **Anti-SSRF:** solo se analizan dominios que resuelven a IPs públicas, y cada redirección se vuelve a validar.
- **Sin XSS ni inyección Markdown:** todo dato que procede del dominio analizado se escapa o se muestra como texto literal. El informe HTML lleva una CSP que bloquea scripts.
- **Contraseñas:** se guardan con PBKDF2-SHA256 (600 000 iteraciones). Hay bloqueo temporal por intentos fallidos y el mensaje de error no revela si el usuario existe.
- **Control de acceso por rol:** un analista solo ve su propio historial.
- **Uso:** límite de análisis por usuario, confirmación de autorización y auditoría con retención limitada.
- **Secretos:** solo en `.env`, que está en `.gitignore`. Las dependencias tienen versión fija y se revisan con `pip-audit` y Dependabot.
- **Contenedor (no validado):** configurado sin root, con sistema de ficheros de solo lectura y sin *capabilities*. Caddy añadiría HSTS, CSP y el resto de cabeceras.

---

## 📄 Licencia

[MIT](LICENSE). Fuentes de datos externas: [crt.sh](https://crt.sh) y [Shodan InternetDB](https://internetdb.shodan.io), consultadas según sus condiciones de uso públicas.
