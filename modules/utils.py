"""
utils.py
--------
Utilidades compartidas: limpieza y validación de dominios, protección
anti-SSRF (solo se analizan destinos con IP pública) y escapado de HTML.
"""

from __future__ import annotations

import html
import ipaddress
import os
import re
import socket

# Longitud máxima de un nombre DNS completo (RFC 1035)
MAX_DOMAIN_LENGTH = 253

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class TargetNotAllowed(ValueError):
    """El destino no se puede analizar (formato inválido o IP no pública)."""


def sanitize_domain(raw: str) -> str:
    """
    Limpia lo que escribe el usuario: espacios, esquema, ruta, puerto y punto final.

    >>> sanitize_domain("  https://Ejemplo.com/ruta?x=1 ")
    'ejemplo.com'
    """
    if raw is None:
        return ""
    value = raw.strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)   # cualquier esquema
    value = re.split(r"[/?#]", value, maxsplit=1)[0]        # quitar ruta y query
    value = value.split("@")[-1]                             # quitar user:pass@
    value = value.split(":")[0]                              # quitar puerto
    return value.rstrip(".")


def validate_domain(domain: str) -> bool:
    """
    Comprueba que la cadena es un nombre de dominio con formato correcto.

    >>> validate_domain("ejemplo.com")
    True
    >>> validate_domain("http://ejemplo.com")
    False
    """
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    return bool(_DOMAIN_RE.match(domain))


def lab_hosts() -> set[str]:
    """
    Hosts de laboratorio permitidos aunque resuelvan a IP privada.

    Se configuran explícitamente con LAB_HOSTS (separados por comas). Sirven
    para hacer demos y pruebas contra un objetivo propio en red local o Docker.
    """
    raw = os.getenv("LAB_HOSTS", "")
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def is_public_ip(ip: str) -> bool:
    """True si la IP es enrutable en Internet (no privada, loopback, enlace local...)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # Las IPv6 que encapsulan una IPv4 (::ffff:10.0.0.1) se evalúan como IPv4
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_ips(host: str) -> list[str]:
    """Resuelve un host a la lista de IPs (v4 y v6) sin duplicados."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    ips: list[str] = []
    for info in infos:
        ip = info[4][0].split("%")[0]   # quitar zona IPv6 (fe80::1%eth0)
        if ip not in ips:
            ips.append(ip)
    return ips


def check_target(host: str) -> list[str]:
    """
    Verifica que un host se puede analizar y devuelve sus IPs.

    Reglas (control anti-SSRF):
      · Formato de dominio válido, salvo que sea un host de laboratorio declarado.
      · Debe resolver a alguna IP.
      · TODAS sus IPs deben ser públicas, salvo hosts de laboratorio.

    Raises:
        TargetNotAllowed: con un mensaje apto para mostrar al usuario.
    """
    host = (host or "").lower()
    is_lab = host in lab_hosts()

    if not is_lab and not validate_domain(host):
        raise TargetNotAllowed(
            "Formato de dominio no válido. Introduce solo el dominio, por ejemplo: ejemplo.com"
        )

    ips = resolve_ips(host)
    if not ips:
        raise TargetNotAllowed("El dominio no resuelve a ninguna dirección IP.")

    if not is_lab:
        blocked = [ip for ip in ips if not is_public_ip(ip)]
        if blocked:
            raise TargetNotAllowed(
                "El dominio resuelve a direcciones internas o reservadas. "
                "Por seguridad solo se analizan destinos con IP pública."
            )
    return ips


def esc(value) -> str:
    """Escapa cualquier valor para insertarlo de forma segura en HTML."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def truncate(value: str, limit: int = 120) -> str:
    """Recorta textos largos para mostrarlos en tablas."""
    value = "" if value is None else str(value)
    return value if len(value) <= limit else value[: limit - 1] + "…"
