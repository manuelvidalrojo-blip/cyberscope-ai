# Seguridad del producto y modelo de amenazas

## 1. Activos

| Activo | Por qué es valioso |
|---|---|
| Credenciales de los usuarios | Dan acceso a la herramienta y al historial |
| Historial de análisis | Revela debilidades de los dominios de la organización: es un mapa para un atacante |
| Clave de la API de Anthropic | Tiene coste económico si se filtra |
| El servidor que ejecuta CyberScope | Desde él se podría alcanzar la red interna (SSRF) o lanzar análisis contra terceros |
| Registro de auditoría | Prueba de uso responsable; contiene IPs (dato personal) |

## 2. Atacantes considerados

- **Usuario anónimo de Internet**, si la app está publicada. Puede intentar fuerza bruta en el *login* o abusar del análisis.
- **Analista legítimo malintencionado o curioso.** Puede intentar ver historiales ajenos, usar la herramienta como trampolín SSRF o analizar dominios sin autorización.
- **Dominio analizado malicioso.** Controla las respuestas: cabeceras, registros TXT, certificados, redirecciones y nombres en crt.sh. Puede intentar XSS, SSRF por redirección, *prompt injection* o agotar recursos.

## 3. Análisis STRIDE

| Categoría | Amenaza | Control aplicado | Evidencia |
|---|---|---|---|
| **S**poofing | Fuerza bruta o *credential stuffing* contra el *login* | PBKDF2-SHA256 (600 000 iteraciones), bloqueo de 15 min tras 5 fallos, mensaje genérico, tiempo constante incluso si el usuario no existe | PR-28, PR-30, PR-31 |
| **S**poofing | Sesión robada o abandonada | Caducidad por inactividad (30 min); protección XSRF de Streamlit activada | `app.py`, `.streamlit/config.toml` |
| **T**ampering | Inyección SQL en el *login* o el historial | Todas las consultas parametrizadas (`?`) | PR-36 |
| **T**ampering | Datos externos que alteran el informe o el dashboard (XSS) | `esc()` sobre todo valor externo; CSP `default-src 'none'` en el informe; Markdown sin HTML en Streamlit | PR-22, PR-23 |
| **T**ampering | *Prompt injection* desde registros TXT o cabeceras hacia el modelo de IA | Al modelo solo se envían datos estructurados y acotados (booleanos, números, listas cerradas), nunca valores en bruto | PR-25 |
| **R**epudiation | Un usuario niega haber analizado un dominio | Auditoría de *login*, análisis (con la confirmación de autorización), rechazos y cambios de usuarios, con usuario, hora e IP | M-02, panel de administración |
| **I**nformation disclosure | Un analista ve análisis de otros | Filtro por propietario en la consulta (`get_analysis(id, username)`) | PR-35 |
| **I**nformation disclosure | Trazas internas visibles al usuario | `showErrorDetails = "none"`; excepciones registradas en el log del servidor, mensaje genérico al usuario | `app.py`, M-10 |
| **I**nformation disclosure | Secretos en el repositorio | `.env` en `.gitignore`; `.env.example` con valores ficticios; historial revisado sin secretos | `.gitignore`, revisión con `git grep` |
| **I**nformation disclosure | **SSRF**: usar la herramienta para alcanzar `localhost`, la red interna o los metadatos de la nube (169.254.169.254) | `check_target()` exige que todas las IPs resueltas sean públicas; cada redirección se revalida; los hosts de laboratorio son una lista explícita | PR-03, PR-04, PR-08, M-02 |
| **D**enial of service | Abuso de la herramienta (muchos análisis) | Límite por usuario (10 cada 10 min), caché de 10 min | PR-34 |
| **D**enial of service | Un dominio que responde con cuerpos enormes o bucles de redirección | Lectura máxima de 512 KB, 5 redirecciones como máximo, *timeouts* en todas las conexiones | PR-09 |
| **D**enial of service | Bloquear a un usuario legítimo fallando su *login* a propósito | **Riesgo aceptado**: el bloqueo es temporal (15 min) y el administrador lo ve en la auditoría | — |
| **E**levation of privilege | Un analista accede a Administración | Rol comprobado en el servidor al pintar la página, no solo ocultando el menú; el intento se audita | `admin_page()`, M-07 |
| **E**levation of privilege | Compromiso del contenedor | Usuario sin privilegios (uid 10001), sistema de ficheros de solo lectura, `cap_drop: ALL`, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` |

## 4. Gestión de secretos

- Los secretos (contraseña inicial del administrador y clave de Anthropic) solo existen en `.env`, que está en `.gitignore`.
- El repositorio incluye `.env.example` con valores ficticios.
- El historial de GitHub se revisó en busca de claves, tokens y contraseñas con `git grep` sobre todos los commits, sin resultados.
- La contraseña inicial solo se usa para crear el administrador la primera vez; después solo se guarda su hash.

## 5. Entradas y validación

| Entrada | Validación |
|---|---|
| Dominio | Limpieza, regex de dominio (≤253 caracteres, etiquetas ≤63), resolución DNS, IP pública y `max_chars=300` en el formulario |
| Usuario y contraseña | Usuario con regex `[A-Za-z0-9_.-]{3,32}`; contraseña de 12+ caracteres con letras y números |
| Respuestas de terceros (dominio, crt.sh, InternetDB) | Se tratan como no confiables: puertos validados como enteros, CVE con regex, subdominios validados como dominio, todo escapado al mostrarse |

## 6. Dependencias

- Versiones fijadas en `requirements.txt`.
- `pip-audit -r requirements.txt` del 15/10/2026: **«No known vulnerabilities found»** (ver `docs/evidencias/pip-audit.txt`).
- Dependabot está configurado para pip, Docker y GitHub Actions, y la CI ejecuta `pip-audit` en cada *push*.

## 7. Datos personales (RGPD)

| Dato | Finalidad | Conservación | Protección |
|---|---|---|---|
| Nombre de usuario | Autenticación y autoría de los análisis | Mientras la cuenta exista | Base de datos local, no expuesta |
| Contraseña | Autenticación | Solo el hash PBKDF2 | Nunca se guarda en claro |
| IP del cliente en la auditoría | Seguridad y detección de abusos (interés legítimo) | 90 días (`AUDIT_RETENTION_DAYS`), con purga automática | Solo visible para administradores |

- Los análisis tratan datos públicos de dominios, no de personas.
- Los registros DNS pueden contener direcciones de correo genéricas; no se extraen ni se procesan.
- Al usar la IA, a Anthropic solo se envía el resumen estructurado de hallazgos, sin datos personales.

## 8. Riesgos residuales

- **DNS rebinding:** entre la validación de la IP y la conexión, el DNS podría cambiar. Mitigación parcial: cada redirección se revalida. La solución completa, conectar a la IP validada fijando SNI, queda como trabajo futuro.
- **Bloqueo de cuentas por terceros:** riesgo aceptado (ver STRIDE, DoS).
- **Sin HTTPS en el servidor de Hetzner** mientras no tenga dominio (RNF-08 parcial).
