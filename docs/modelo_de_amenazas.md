# Seguridad del producto y modelo de amenazas

## 1. Activos

| Activo | Por qué es valioso |
|---|---|
| Credenciales de los usuarios | Dan acceso a la herramienta y al historial |
| Historial de análisis | Revela debilidades de los dominios de la organización: es un mapa para un atacante |
| Clave de la API de Anthropic | Tiene coste económico si se filtra |
| El servidor que ejecuta CyberScope | Desde él se podría alcanzar la red interna (SSRF) o lanzar análisis contra terceros |
| Registro de auditoría | Prueba de uso responsable; contiene nombres de usuario y un campo IP (dato personal; en la práctica vacío o la IP del proxy, ver §7) |

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
| **T**ampering | Inyección Markdown en el dashboard (imagen de rastreo o enlace de *phishing* en la cabecera `Server`, el emisor TLS o los registros DNS) | Valores externos mostrados con `st.text` (texto literal) mediante `plain_field()`. Fallo encontrado y corregido en la auditoría pre-push | M-12 |
| **T**ampering | *Prompt injection* desde registros TXT o cabeceras hacia el modelo de IA | Al modelo solo se envían datos estructurados y acotados (booleanos, números, listas cerradas), nunca valores en bruto | PR-25 |
| **R**epudiation | Un usuario niega haber analizado un dominio | Auditoría de *login*, análisis (con la confirmación de autorización), rechazos y cambios de usuarios, con usuario y hora (la IP solo si Streamlit la proporciona, ver §7) | M-02, panel de administración |
| **I**nformation disclosure | Un analista ve análisis de otros | Filtro por propietario en la consulta (`get_analysis(id, username)`) | PR-35 |
| **I**nformation disclosure | Trazas internas visibles al usuario | `showErrorDetails = "none"`; excepciones registradas en el log del servidor, mensaje genérico al usuario | `app.py`, M-10 |
| **I**nformation disclosure | Secretos en el repositorio | `.env` en `.gitignore`; `.env.example` con valores ficticios; `gitleaks` sobre todo el historial | `docs/evidencias/gitleaks.txt` |
| **I**nformation disclosure | **SSRF**: usar la herramienta para alcanzar `localhost`, la red interna o los metadatos de la nube (169.254.169.254) | `check_target()` exige que todas las IPs resueltas sean públicas; cada redirección se revalida; los hosts de laboratorio son una lista explícita | PR-03, PR-04, PR-08, M-02 |
| **D**enial of service | Abuso de la herramienta (muchos análisis) | Límite por usuario (10 cada 10 min), caché de 10 min | PR-34 |
| **D**enial of service | Un dominio que responde con cuerpos enormes, bucles de redirección o una `Location` malformada | Lectura máxima de 512 KB, 5 redirecciones como máximo, *timeouts* en todas las conexiones, URL malformada → error controlado | PR-09, PR-38 |
| **D**enial of service | Bloquear a un usuario legítimo fallando su *login* a propósito | **Riesgo aceptado**: el bloqueo es temporal (15 min) y el administrador lo ve en la auditoría | — |
| **E**levation of privilege | Un analista accede a Administración | Rol comprobado en el servidor al pintar la página, no solo ocultando el menú; el intento se audita | `admin_page()`, M-07 |
| **E**levation of privilege | Compromiso del contenedor | Usuario sin privilegios (uid 10001), sistema de ficheros de solo lectura, `cap_drop: ALL`, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` |

## 4. Gestión de secretos

- **Dónde están:** la contraseña inicial del administrador (`CYBERSCOPE_ADMIN_PASSWORD`) y la clave de Anthropic (`ANTHROPIC_API_KEY`) solo se leen de variables de entorno o de `.env`.
  - `.env` está en `.gitignore`: comprobado con `git check-ignore .env`.
  - En disco, `.env` está en texto plano.
- **Qué hay en la base de datos:** nunca se guarda la clave de API. La contraseña del administrador solo se guarda como hash PBKDF2.
- **Qué hay en el repositorio:** solo `.env.example`, con valores ficticios.
- **`gitleaks` 8.30.1 (`gitleaks detect --log-opts="--all"`, 20 commits):**
  - 1 hallazgo: `CYBERSCOPE_ADMIN_PASSWORD` en `.env.example`. Es la credencial de prueba documentada en el README, no un secreto real.
  - Registrado como falso positivo justificado en `.gitleaksignore`. Tras ello: «no leaks found».
  - Riesgo residual: la credencial por defecto es pública y la app no obliga a cambiarla (ver `limitaciones.md`).

## 5. Entradas y validación

| Entrada | Validación |
|---|---|
| Dominio | Limpieza, regex de dominio (≤253 caracteres, etiquetas ≤63), resolución DNS, todas las IPs públicas y `max_chars=300` en el formulario |
| Usuario y contraseña | Usuario con regex `[A-Za-z0-9_.-]{3,32}`; contraseña de 12+ caracteres con letras y números |
| Respuestas de terceros (dominio, crt.sh, InternetDB) | Se tratan como no confiables: puertos validados como enteros, CVE con regex, subdominios validados como dominio, URLs de redirección validadas, todo escapado en HTML o mostrado como texto literal |

## 6. Dependencias

Resultados reales del 15/10/2026:

- `pip-audit -r requirements.txt` (dependencias de la app): **«No known vulnerabilities found»**.
- `pip-audit` sobre el entorno virtual completo: vulnerabilidades en **`pip` 25.3** (el que trae Python 3.14.3; corregidas en 26.x). `pip` no es una dependencia de la app; se recomienda actualizarlo en el README. La imagen Docker lo actualiza en su construcción.
- Versiones fijadas en `requirements.txt`. Dependabot está configurado y la CI ejecuta `pip-audit` en cada *push* (activa al subir el repositorio).

## 7. Datos almacenados (comportamiento real del código)

**Dónde:** un único fichero SQLite, `DATA_DIR/cyberscope.db`.

- Por defecto, `./data/cyberscope.db` relativo al directorio desde el que se arranca la app.
- En Docker, el volumen `cyberscope-data` en `/app/data` (no validado).
- El fichero no está cifrado y usa los permisos por defecto del sistema.

| Tabla | Campos | ¿Usuario? | ¿IP? | ¿Dominio? | ¿Fecha? | ¿Secretos? | Conservación real |
|---|---|---|---|---|---|---|---|
| `users` | usuario, hash de contraseña, rol, activo, `created_at`, `last_login` | Sí | No | No | Sí | Solo el hash PBKDF2 | **Indefinida**. No hay borrado de usuarios, solo desactivación |
| `login_attempts` | usuario **tal como se escribió** (incluso si no existe), IP, éxito, fecha | Sí | Sí\* | No | Sí | No. Si alguien escribe su contraseña en el campo «Usuario», quedaría guardada | `AUDIT_RETENTION_DAYS` (90 por defecto), **purgado solo al arrancar** la app o `manage_users.py` |
| `audit_log` | fecha, usuario, evento, detalle (dominios analizados, puntuación, motivo de rechazo, usuarios creados), IP | Sí | Sí\* | Sí | Sí | No | Igual que `login_attempts` |
| `analyses` | usuario, dominio, fecha, puntuación, riesgo, JSON completo del análisis | Sí | IPs **del dominio analizado**, no del usuario | Sí | Sí | No | **Indefinida**. No hay función de borrado |

\* **IP real registrada:**

- En accesos por `localhost`, Streamlit no informa de la IP y se guarda vacía (`None`). Comprobado en la instalación limpia (M-11).
- Detrás de Caddy previsiblemente se guardaría la IP del contenedor del proxy, no la del cliente (no validado).
- En la práctica, la auditoría actual **no** identifica la IP del usuario final.

El JSON de `analyses` contiene datos **públicos** del dominio: IPs, registros DNS, certificado, cabeceras, puertos según InternetDB, subdominios de crt.sh, el resumen ejecutivo y el nombre del analista.

**Fuera de la base de datos:**

- **En memoria:**
  - sesión del navegador: usuario, rol y último análisis;
  - caché de análisis de 10 min, compartida entre usuarios y sin nombre de analista.
- **Logs del proceso (salida estándar):** creación del administrador inicial y trazas de errores inesperados (incluyen el dominio). No se guardan en fichero.
- **Ficheros descargados por el usuario:**
  - el informe HTML incluye el nombre del analista;
  - el JSON incluye el análisis completo y el analista.
- **Terceros:**
  - el **dominio** se envía a crt.sh;
  - las **IPs del dominio**, a Shodan InternetDB;
  - con clave de API, el **resumen estructurado de hallazgos** (con el nombre del dominio), a Anthropic.
  - No se envían nombres de usuario ni IPs de los usuarios.

**Valoración RGPD:** los datos personales tratados son el nombre de usuario de los analistas y, potencialmente, su IP. La finalidad es la autenticación y la trazabilidad del uso ético (interés legítimo). Los puntos débiles reales están en `limitaciones.md` §5: historial sin caducidad, purga solo al arrancar y sin función de supresión.

## 8. Riesgos residuales

Ver la lista completa en [`limitaciones.md`](limitaciones.md) §4. Los principales:

- DNS rebinding (mitigación parcial).
- Credencial por defecto pública.
- Redirecciones a puertos arbitrarios de hosts públicos.
- Bloqueo de cuentas por terceros.
- CSP permisiva.
- Exposición en la LAN con `streamlit run app.py`.
- Base de datos sin cifrar.
- Sin HTTPS en Hetzner.
