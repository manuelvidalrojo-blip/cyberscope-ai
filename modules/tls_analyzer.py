"""
tls_analyzer.py
---------------
Análisis del certificado TLS del dominio (puerto 443).

Hace un único handshake TLS, como un navegador, y extrae: emisor, sujeto,
fechas de validez, días hasta la caducidad, nombres alternativos (SAN),
versión de TLS negociada y cifrado. Si la verificación falla se informa
del motivo (certificado caducado, autofirmado, nombre que no coincide...).
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

TIMEOUT = 8
PORT = 443
EXPIRY_WARNING_DAYS = 30

# Versiones consideradas seguras hoy en día
SECURE_VERSIONS = {"TLSv1.2", "TLSv1.3"}


def analyze_tls(domain: str) -> dict:
    """
    Analiza el certificado TLS y la versión de protocolo de un dominio.

    Returns:
        dict con trusted, issuer, subject, not_before, not_after, days_left,
        san, tls_version, cipher, secure_version, expiring_soon y error.
    """
    result = {
        "domain":         domain,
        "trusted":        False,
        "issuer":         None,
        "subject":        None,
        "not_before":     None,
        "not_after":      None,
        "days_left":      None,
        "san":            [],
        "tls_version":    None,
        "cipher":         None,
        "secure_version": False,
        "expiring_soon":  False,
        "error":          None,
    }

    context = ssl.create_default_context()   # verifica cadena y nombre del host
    try:
        with socket.create_connection((domain, PORT), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                result["tls_version"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = cipher[0] if cipher else None
    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"Certificado no confiable: {exc.verify_message or 'verificación fallida'}."
        return result
    except ssl.SSLError as exc:
        result["error"] = f"Error en el handshake TLS ({exc.reason or 'desconocido'})."
        return result
    except socket.timeout:
        result["error"] = f"Tiempo de espera agotado al conectar al puerto {PORT}."
        return result
    except OSError:
        result["error"] = f"No se pudo conectar al puerto {PORT} (HTTPS no disponible)."
        return result

    result.update(parse_certificate(cert))
    result["trusted"] = True
    result["secure_version"] = result["tls_version"] in SECURE_VERSIONS
    return result


def parse_certificate(cert: dict, now: datetime | None = None) -> dict:
    """
    Convierte el dict de ssl.getpeercert() en campos legibles.

    Separado de analyze_tls() para poder probarlo sin conexión de red.
    """
    now = now or datetime.now(timezone.utc)
    not_before = _parse_date(cert.get("notBefore"))
    not_after = _parse_date(cert.get("notAfter"))
    days_left = (not_after - now).days if not_after else None

    return {
        "issuer":        _name(cert.get("issuer", ())),
        "subject":       _name(cert.get("subject", ())),
        "not_before":    not_before.date().isoformat() if not_before else None,
        "not_after":     not_after.date().isoformat() if not_after else None,
        "days_left":     days_left,
        "san":           [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"][:50],
        "expiring_soon": days_left is not None and days_left < EXPIRY_WARNING_DAYS,
    }


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    # Formato de OpenSSL: 'Jun  1 12:00:00 2026 GMT'
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)


def _name(rdns) -> str | None:
    """Une los campos del nombre distinguido priorizando O y CN."""
    fields = {}
    for rdn in rdns:
        for key, value in rdn:
            fields[key] = value
    parts = [fields.get("organizationName"), fields.get("commonName")]
    text = " · ".join(p for p in parts if p)
    return text or None
