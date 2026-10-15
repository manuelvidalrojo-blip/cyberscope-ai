# CyberScope AI · imagen de producción
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATA_DIR=/app/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app.py .
COPY modules/ modules/
COPY scripts/ scripts/
COPY .streamlit/ .streamlit/

# Usuario sin privilegios: la app nunca corre como root dentro del contenedor
RUN useradd --create-home --uid 10001 cyberscope \
    && mkdir -p /app/data \
    && chown -R cyberscope:cyberscope /app/data
USER cyberscope

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=4)"

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
