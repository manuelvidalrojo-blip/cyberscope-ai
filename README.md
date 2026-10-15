# 🛡️ CyberScope AI

**CyberScope AI** es una herramienta web de ciberseguridad (línea *Blue Team*) que analiza de forma **pasiva** la exposición externa de un dominio autorizado. Reúne en un solo panel lo que normalmente exige varias herramientas: `curl`, `dig`, securityheaders.com, crt.sh, Shodan...

Para cada dominio calcula una **puntuación de 0 a 100** y genera **recomendaciones priorizadas**. Redacta además un **resumen ejecutivo**, con IA (Claude) o por reglas, y exporta un **informe** en HTML, Markdown o JSON.

> ⚠️ **Uso ético exclusivamente.** Utiliza la herramienta solo sobre dominios de tu propiedad o con autorización expresa del propietario. La aplicación exige confirmarlo y registra cada análisis en un log de auditoría.

| Versión | Entrega |
|---|---|
| v1.0 (mayo 2026) | Práctica 1: prototipo con HTTPS, cabeceras, DNS, puntuación e informe HTML |
| **v2.0 (octubre 2026)** | **Práctica 3: producto funcional (este README). Etiqueta `v1.0-practica3`** |

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
| Puntuación | 0-100 en cuatro áreas ponderadas, más una penalización por servicios peligrosos expuestos |
| Resumen ejecutivo | Con la API de Claude si hay clave; si no, por reglas, indicado de forma explícita |
| Informes | HTML autocontenido (imprimible a PDF), Markdown y JSON |
| Historial | Cada análisis queda guardado en SQLite, con gráfica de evolución por dominio |
| Usuarios | Login con roles `admin` / `analyst`, bloqueo tras 5 intentos fallidos y límite de análisis por usuario |
| Auditoría | Registro de logins, análisis, rechazos y cambios de usuarios |

---

## 📋 Requisitos previos

- **Opción A (recomendada):** Docker 24+ con Docker Compose v2.
- **Opción B (local):** Python **3.11 o superior** y `git`.
- Conexión a Internet: los análisis consultan el dominio, crt.sh y Shodan InternetDB.
- *(Opcional)* Una clave de la API de Anthropic para el resumen con IA.

---

## 🚀 Instalación y ejecución

### Opción A · Docker (recomendada)

```bash
git clone https://github.com/manuelvidalrojo-blip/cyberscope-ai.git
cd cyberscope-ai
cp .env.example .env          # edita al menos CYBERSCOPE_ADMIN_PASSWORD
docker compose up -d --build
```

Abre **http://localhost** (Caddy publica el puerto 80). Para un servidor con dominio, pon `SITE_ADDRESS=tudominio.com` en `.env`: Caddy obtiene el certificado de Let's Encrypt y sirve la app por HTTPS.

### Opción B · Python local

```bash
git clone https://github.com/manuelvidalrojo-blip/cyberscope-ai.git
cd cyberscope-ai
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # en Windows: copy .env.example .env
streamlit run app.py
```

La aplicación se abre en **http://localhost:8501**.

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

### Demo con objetivo de laboratorio

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
| `AUDIT_RETENTION_DAYS` | 90 | Días que se conserva la auditoría (contiene IPs) |
| `DATA_DIR` | `data` | Carpeta de la base de datos SQLite |
| `LAB_HOSTS` | vacío | Hosts de laboratorio permitidos con IP privada |
| `SITE_ADDRESS` | `:80` | Dominio para Caddy (HTTPS automático) |

---

## 🧪 Pruebas

```bash
pip install -r requirements-dev.txt
pytest -v                       # 69 pruebas automáticas, sin acceso a red
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
├── docs/                     # Requisitos, trazabilidad, pruebas, modelo de amenazas
├── deploy/                   # Caddyfile y objetivo de laboratorio
├── Dockerfile · docker-compose.yml
├── .env.example              # Variables necesarias con valores ficticios
├── requirements.txt          # Dependencias fijadas
└── requirements-dev.txt      # + pytest y pip-audit
```

---

## 🔐 Seguridad

Resumen de los controles. El detalle está en [`docs/modelo_de_amenazas.md`](docs/modelo_de_amenazas.md).

- **Anti-SSRF:** solo se analizan dominios que resuelven a IPs públicas, y cada redirección se vuelve a validar.
- **Sin XSS:** todo dato que procede del dominio analizado se escapa. El informe HTML lleva una CSP que bloquea scripts.
- **Contraseñas:** se guardan con PBKDF2-SHA256 (600 000 iteraciones). Hay bloqueo temporal por intentos fallidos y el mensaje de error no revela si el usuario existe.
- **Control de acceso por rol:** un analista solo ve su propio historial.
- **Uso:** límite de análisis por usuario, confirmación de autorización y auditoría con retención limitada.
- **Secretos:** solo en `.env`, que está en `.gitignore`. Las dependencias tienen versión fija y se revisan con `pip-audit` y Dependabot.
- **Contenedor:** se ejecuta sin root, con sistema de ficheros de solo lectura y sin *capabilities*. Caddy añade HSTS, CSP y el resto de cabeceras de seguridad.

---

## 📄 Licencia

[MIT](LICENSE). Fuentes de datos externas: [crt.sh](https://crt.sh) y [Shodan InternetDB](https://internetdb.shodan.io), consultadas según sus condiciones de uso públicas.
