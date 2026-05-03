# 🛡️ CyberScope AI

**CyberScope AI** es una herramienta web de ciberseguridad para analizar la exposición externa de un dominio autorizado.

Permite auditar de forma pasiva la superficie de ataque visible: cabeceras HTTP, puertos expuestos, configuración DNS, certificados TLS y posibles vulnerabilidades comunes, todo desde una interfaz web intuitiva construida con Streamlit.

> ⚠️ **Uso ético exclusivamente.** Utiliza esta herramienta solo sobre dominios de tu propiedad o con autorización expresa del propietario.

---

## 📁 Estructura del proyecto

```
cyberscope_ai/
├── app.py                  # Interfaz principal Streamlit
├── requirements.txt        # Dependencias Python
├── README.md
├── modules/
│   ├── __init__.py
│   ├── scanner.py          # Escaneo de puertos y DNS
│   ├── headers.py          # Análisis de cabeceras HTTP
│   ├── scoring.py          # Puntuación de riesgo
│   ├── ai_report.py        # Generación de informe con IA
│   └── utils.py            # Utilidades compartidas
├── reports/                # Informes exportados
└── screenshots/            # Capturas de resultados
```

---

## 🚀 Cómo ejecutarlo localmente

### 1. Clona el repositorio

```bash
git clone https://github.com/tu-usuario/cyberscope-ai.git
cd cyberscope-ai
```

### 2. Crea un entorno virtual (recomendado)

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Instala las dependencias

```bash
pip install -r requirements.txt
```

### 4. Lanza la aplicación

```bash
streamlit run app.py
```

La aplicación se abrirá automáticamente en `http://localhost:8501`.

---

## 🧩 Módulos (en desarrollo)

| Módulo | Descripción |
|---|---|
| `scanner.py` | Resolución DNS, puertos comunes, detección de tecnologías |
| `headers.py` | Análisis de cabeceras HTTP de seguridad |
| `scoring.py` | Cálculo de puntuación de riesgo global |
| `ai_report.py` | Redacción de informe ejecutivo asistido por IA |
| `utils.py` | Funciones compartidas (validación, formateo, logs) |

---

## 📄 Licencia

MIT — libre para uso personal y profesional con fines éticos.
