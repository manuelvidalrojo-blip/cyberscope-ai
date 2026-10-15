# Limitaciones conocidas

Estado a 15/10/2026, tras la auditoría pre-entrega. Nada de esta lista se oculta en la memoria ni en el vídeo.

## 1. No validado en el entorno de desarrollo

| Elemento | Estado | Motivo | Qué se ha hecho |
|---|---|---|---|
| **Docker** (`Dockerfile`, `docker-compose.yml`) | **NO VALIDADO EN ESTE ENTORNO** | Docker no está instalado en el equipo de desarrollo | Solo revisión estática (ver apartado 6). La ruta demostrada es la instalación con Python |
| **Caddy** (`deploy/Caddyfile`) | **NO VALIDADO** | Depende de Docker | Revisión estática |
| **Objetivo de laboratorio** (`lab-target`) | **NO VALIDADO** | Depende de Docker | Revisión estática. Las demos se hacen sobre `example.org` |
| **Resumen con la API de Claude** | **NO VALIDADO** | No hay `ANTHROPIC_API_KEY` disponible | El modo por reglas **sí está probado** (M-01 y PR-24). La integración con la API solo se prueba con respuestas simuladas (PR-26 y PR-27) |
| **Otras versiones de Python** | Solo validado con **Python 3.14.3** en Windows 11 | — | El mínimo declarado es 3.11, porque `pandas` 3 lo exige, pero 3.11-3.13 no se han probado. La imagen Docker usa 3.12 (no validada) |

## 2. Despliegue en Hetzner

- **Despliegue actual (sin cambios):** sigue en marcha la versión de la Práctica 1, servida por **HTTP** en `http://178.105.151.227` (puerto 80) y sin cabeceras de seguridad. No se ha modificado el servidor en la Práctica 3.
- **HTTPS en producción pendiente:** el servidor solo tiene IP, sin dominio, así que Let's Encrypt no puede emitir un certificado para él. El Caddyfile lo resolvería al configurar `SITE_ADDRESS` con un dominio, pero no se ha probado.
- **La entrega se demuestra en local** (`streamlit run app.py`), tal como permite el enunciado (FAQ: «Basta con que funcione en local o en contenedores siguiendo el README»).

## 3. Dependencia de servicios externos

- **crt.sh:** es lento y a menudo devuelve 502/503 o *timeouts*. Si falla, la pestaña de subdominios muestra el error y el resto del análisis continúa (RNF-02).
- **Shodan InternetDB:** los datos pueden tener días o semanas de antigüedad y no son un escaneo en tiempo real. Su uso gratuito es para fines no comerciales.
- **API de Anthropic:** si falla, se usa el resumen por reglas y se indica en la interfaz.
- **Red local:** desde la red de desarrollo, `example.com` no es accesible (conexión reseteada; `curl` también falla), así que las pruebas usan `example.org`.

## 4. Seguridad: riesgos residuales

| Riesgo | Detalle |
|---|---|
| Credencial por defecto conocida | `.env.example` y el README publican `admin` / `CambiaEstaClave2026` como credencial de prueba. Si alguien despliega sin cambiarla, cualquiera puede entrar. La app **no obliga** a cambiarla. `gitleaks` la detecta; está marcada como falso positivo justificado en `.gitleaksignore` porque es un valor de ejemplo documentado |
| DNS rebinding | Entre la validación de IP y la conexión, el DNS podría cambiar. Solo se mitiga revalidando cada redirección |
| Redirecciones a otros puertos | Si el dominio analizado redirige a `http://host-público:puerto/`, CyberScope sigue la redirección como un navegador (máx. 5). No puede dirigirse a IPs internas, pero sí a puertos arbitrarios de hosts públicos |
| Bloqueo de cuentas por terceros | Quien conozca un nombre de usuario puede bloquearlo 15 min fallando 5 veces (riesgo aceptado) |
| CSP de la app permisiva | Streamlit necesita `'unsafe-inline'` y `'unsafe-eval'`; el Caddyfile también permite `ws:`/`wss:` a cualquier host |
| Exposición en red local | `streamlit run app.py` escucha en todas las interfaces (`:::8501`), así que es accesible desde la LAN. Para uso solo local: `--server.address 127.0.0.1` |
| Permisos de la base de datos | `data/cyberscope.db` se crea con los permisos por defecto del sistema y no está cifrada. Contiene hashes de contraseñas e historial |
| `pip` del entorno virtual | `pip-audit` del entorno completo detecta vulnerabilidades en `pip` 25.3 (el que trae Python 3.14.3). No es una dependencia de la app; se corrige con `python -m pip install --upgrade pip` |

## 5. Funcionales y de privacidad

- **PDF:** no hay botón de PDF (RF-14 modificado); se obtiene imprimiendo el HTML.
- **Caché de 10 min:** si el mismo dominio se vuelve a analizar en ese plazo, se devuelven los resultados en caché (con la hora del primer análisis). Se comparte entre usuarios.
- **Historial sin caducidad:** los análisis se conservan indefinidamente y no hay función para borrarlos ni para eliminar usuarios (solo desactivarlos).
- **Purga de auditoría solo al arrancar:** los registros de más de `AUDIT_RETENTION_DAYS` se borran al iniciar la app o el script `manage_users.py`, no de forma periódica.
- **IP en la auditoría:** en accesos por `localhost` Streamlit no informa de la IP y se guarda vacía (`None`), como se comprobó en la instalación limpia. Detrás de Caddy previsiblemente se guardaría la IP del proxy, no la del cliente (no validado).
- **Integraciones con VirusTotal / HIBP:** descartadas (RF-18).
- **Null MX:** un registro MX nulo (`0 .`, «este dominio no recibe correo») se muestra como `0 ` en lugar de explicarse.
- **Coherencia del SPF `+all`:** recibe 6 de 12 puntos aunque se recomiende con severidad Alta (ver `alcance.md`).
- **Primera carga:** en el primer arranque, la creación del administrador puede recargar el formulario de login mientras se escribe. Basta con volver a escribir.
- **Traducción del navegador:** Chrome puede traducir automáticamente la interfaz. Conviene desactivarlo para la demo.

## 6. Revisión estática de Docker (sin ejecutar)

| Fichero | Observación | Impacto |
|---|---|---|
| `Dockerfile` | Imagen base `python:3.12-slim` por etiqueta, no por *digest* | Construcciones no idénticas en el tiempo |
| `Dockerfile` | Copia `scripts/`, pero `.dockerignore` excluye `tests/` y `docs/` (correcto) | — |
| `docker-compose.yml` | `read_only: true` con `tmpfs` en `/tmp` y `/home/cyberscope`; no se ha comprobado que Streamlit no escriba en otra ruta | Posible fallo de arranque; requiere validación |
| `docker-compose.yml` | `env_file: .env` es obligatorio: si no existe, `docker compose` falla (el README indica crearlo) | — |
| `docker-compose.yml` | Publica el 443 aunque `SITE_ADDRESS=:80` | Sin efecto práctico |
| `Caddyfile` | Envía HSTS también por HTTP (los navegadores lo ignoran en HTTP) | Ninguno |
| `Caddyfile` | CSP con `'unsafe-eval'` y `ws: wss:` amplios | Ver riesgos residuales |
| General | La IP registrada en la auditoría será la del contenedor de Caddy | Auditoría menos útil |
