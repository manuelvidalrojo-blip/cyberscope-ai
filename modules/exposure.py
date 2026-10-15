"""
exposure.py
-----------
Puertos y servicios expuestos SIN escanear: se consulta Shodan InternetDB
(https://internetdb.shodan.io), una base de datos pública y gratuita con lo
que Shodan ha observado en cada IP. Así se mantiene el compromiso de la
Práctica 1 de hacer solo reconocimiento pasivo.

Los datos pueden tener días o semanas de antigüedad: es información
indicativa, no un escaneo en tiempo real.
"""

from __future__ import annotations

import re

import requests

from modules.utils import is_public_ip

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
TIMEOUT = 8
MAX_IPS = 4

# Puertos que no deberían estar abiertos a Internet en casi ningún caso
RISKY_PORTS = {
    21:    "FTP (credenciales en claro)",
    23:    "Telnet (credenciales en claro)",
    445:   "SMB",
    1433:  "Microsoft SQL Server",
    2375:  "API de Docker sin TLS",
    3306:  "MySQL",
    3389:  "Escritorio remoto (RDP)",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    9200:  "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def analyze_exposure(ips: list[str]) -> dict:
    """
    Consulta InternetDB para cada IP pública (máximo MAX_IPS).

    Returns:
        dict con hosts (detalle por IP), open_ports (unión), risky_ports,
        vulns (CVE), source y error.
    """
    result = {
        "hosts":       [],
        "open_ports":  [],
        "risky_ports": [],
        "vulns":       [],
        "source":      "Shodan InternetDB (datos pasivos, pueden no estar actualizados)",
        "error":       None,
    }

    public_ips = [ip for ip in ips if is_public_ip(ip)][:MAX_IPS]
    if not public_ips:
        result["error"] = "No hay IPs públicas que consultar."
        return result

    failures = 0
    for ip in public_ips:
        try:
            host = query_internetdb(ip)
        except requests.exceptions.RequestException:
            failures += 1
            continue
        result["hosts"].append(host)

    if failures == len(public_ips):
        result["error"] = "No se pudo consultar Shodan InternetDB (servicio no disponible)."
        return result

    ports = sorted({p for h in result["hosts"] for p in h["ports"]})
    result["open_ports"] = ports
    result["risky_ports"] = [{"port": p, "service": RISKY_PORTS[p]} for p in ports if p in RISKY_PORTS]
    result["vulns"] = sorted({v for h in result["hosts"] for v in h["vulns"]})
    return result


def query_internetdb(ip: str) -> dict:
    """
    Consulta una IP en InternetDB. Un 404 significa "sin datos" (no es un error).

    Raises:
        requests.exceptions.RequestException si el servicio falla.
    """
    response = requests.get(INTERNETDB_URL.format(ip=ip), timeout=TIMEOUT)
    if response.status_code == 404:
        return {"ip": ip, "ports": [], "vulns": [], "cpes": [], "hostnames": []}
    response.raise_for_status()
    return parse_internetdb(ip, response.json())


def parse_internetdb(ip: str, data: dict) -> dict:
    """Normaliza y valida la respuesta (no confiamos ciegamente en datos externos)."""
    ports = [p for p in data.get("ports", []) if isinstance(p, int) and 0 < p < 65536]
    vulns = [v for v in data.get("vulns", []) if isinstance(v, str) and _CVE_RE.match(v)]
    cpes = [str(c)[:120] for c in data.get("cpes", [])][:20]
    hostnames = [str(h)[:253] for h in data.get("hostnames", [])][:20]
    return {"ip": ip, "ports": sorted(ports), "vulns": sorted(vulns), "cpes": cpes, "hostnames": hostnames}
