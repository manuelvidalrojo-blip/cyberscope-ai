"""
http_client.py
--------------
Cliente HTTP común para todos los módulos que hablan con el dominio analizado.

Diferencias con un requests.get() normal:
  · Sigue las redirecciones a mano (máx. MAX_REDIRECTS) y valida cada salto
    con check_target(): una redirección hacia 127.0.0.1 o 169.254.169.254
    se corta (protección anti-SSRF).
  · Descarga como mucho MAX_BODY_BYTES del cuerpo: solo nos interesan las
    cabeceras y no queremos que un servidor nos haga descargar gigas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from modules.utils import TargetNotAllowed, check_target

TIMEOUT = 10
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 512 * 1024
USER_AGENT = "CyberScope-AI/2.0 (+analisis pasivo autorizado)"


class FetchError(Exception):
    """Error de red al contactar con el dominio (mensaje apto para el usuario)."""


@dataclass
class FetchResult:
    url: str                       # URL final tras redirecciones
    status_code: int
    headers: dict                  # cabeceras de la respuesta final (case-insensitive)
    redirect_chain: list = field(default_factory=list)   # URLs intermedias


def safe_get(url: str, timeout: int = TIMEOUT) -> FetchResult:
    """
    GET con redirecciones validadas.

    Raises:
        FetchError: SSL, conexión, timeout, demasiadas redirecciones o
                    redirección hacia un destino no permitido.
    """
    chain: list[str] = []
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        try:
            host = urlparse(current).hostname or ""
        except ValueError as exc:
            # Location malformada enviada por el servidor (p. ej. "http://[invalido/")
            raise FetchError("El servidor devolvió una redirección con una URL no válida.") from exc
        try:
            check_target(host)
        except TargetNotAllowed as exc:
            raise FetchError(f"Redirección bloqueada hacia un destino no permitido. {exc}") from exc

        try:
            response = requests.get(
                current,
                timeout=timeout,
                allow_redirects=False,
                stream=True,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.exceptions.SSLError as exc:
            raise FetchError("Error SSL: el certificado no es válido, ha caducado o no coincide con el dominio.") from exc
        except requests.exceptions.Timeout as exc:
            raise FetchError(f"Tiempo de espera agotado tras {timeout} segundos.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise FetchError("No se pudo conectar. Comprueba que el dominio existe y es accesible.") from exc
        except requests.exceptions.RequestException as exc:
            raise FetchError("Error inesperado al conectar con el dominio.") from exc

        try:
            # Leemos como mucho MAX_BODY_BYTES y cerramos la conexión
            response.raw.read(MAX_BODY_BYTES, decode_content=False)
        except Exception:
            pass
        finally:
            response.close()

        location = response.headers.get("Location")
        if response.is_redirect and location:
            chain.append(current)
            try:
                current = urljoin(current, location)
            except ValueError as exc:
                raise FetchError("El servidor devolvió una redirección con una URL no válida.") from exc
            continue

        return FetchResult(
            url=current,
            status_code=response.status_code,
            headers=response.headers,
            redirect_chain=chain,
        )

    raise FetchError(f"Demasiadas redirecciones (más de {MAX_REDIRECTS}).")
