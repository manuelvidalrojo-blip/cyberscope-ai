"""PR-01 a PR-05 · RF-01 y RNF-07: entrada, validación y protección anti-SSRF."""

import pytest

from modules import utils
from modules.utils import TargetNotAllowed, check_target, is_public_ip, sanitize_domain, validate_domain


@pytest.mark.parametrize("raw, expected", [
    ("Ejemplo.com", "ejemplo.com"),
    ("  https://Ejemplo.com/ruta?x=1 ", "ejemplo.com"),
    ("http://user:pass@ejemplo.com:8080/", "ejemplo.com"),
    ("ftp://ejemplo.com", "ejemplo.com"),
    ("ejemplo.com.", "ejemplo.com"),
    ("", ""),
])
def test_pr01_sanitize_domain(raw, expected):
    """PR-01 · RF-01: la entrada se limpia (esquema, ruta, credenciales, puerto)."""
    assert sanitize_domain(raw) == expected


@pytest.mark.parametrize("domain, valid", [
    ("ejemplo.com", True),
    ("sub.dominio.co.uk", True),
    ("xn--espaa-rta.es", True),           # dominio internacional en punycode
    ("localhost", False),
    ("127.0.0.1", False),
    ("ejemplo..com", False),
    ("-ejemplo.com", False),
    ("ejemplo.com; rm -rf /", False),
    ("<script>.com", False),
    ("a" * 64 + ".com", False),
])
def test_pr02_validate_domain(domain, valid):
    """PR-02 · RF-01: solo se aceptan nombres de dominio con formato válido."""
    assert validate_domain(domain) is valid


@pytest.mark.parametrize("ip, public", [
    ("192.0.2.10", False),      # TEST-NET-1 (documentación): no enrutable
    ("8.8.8.8", True),
    ("10.0.0.5", False),
    ("192.168.1.1", False),
    ("127.0.0.1", False),
    ("169.254.169.254", False),  # metadatos de la nube
    ("::1", False),
    ("::ffff:10.0.0.1", False),  # IPv4 privada encapsulada en IPv6
    ("2001:4860:4860::8888", True),
    ("no-es-ip", False),
])
def test_pr03_is_public_ip(ip, public):
    """PR-03 · RNF-07: clasificación de IPs públicas frente a internas/reservadas."""
    assert is_public_ip(ip) is public


def test_pr04_ssrf_internal_targets_blocked(monkeypatch):
    """PR-04 · RNF-07: un dominio que resuelve a una IP interna se rechaza (anti-SSRF)."""
    monkeypatch.setattr(utils, "resolve_ips", lambda host: ["169.254.169.254"])
    with pytest.raises(TargetNotAllowed, match="internas"):
        check_target("trampa.ejemplo.com")

    # Basta con que UNA de las IPs sea interna
    monkeypatch.setattr(utils, "resolve_ips", lambda host: ["8.8.8.8", "10.0.0.1"])
    with pytest.raises(TargetNotAllowed):
        check_target("mixto.ejemplo.com")


def test_pr05_check_target_cases(monkeypatch):
    """PR-05 · RF-01: dominio público válido aceptado; formato inválido o sin DNS rechazado; laboratorio permitido."""
    monkeypatch.setattr(utils, "resolve_ips", lambda host: ["8.8.8.8"])
    assert check_target("ejemplo.com") == ["8.8.8.8"]

    with pytest.raises(TargetNotAllowed, match="Formato"):
        check_target("no valido")

    monkeypatch.setattr(utils, "resolve_ips", lambda host: [])
    with pytest.raises(TargetNotAllowed, match="no resuelve"):
        check_target("inexistente.ejemplo.com")

    # Host de laboratorio declarado explícitamente: se permite aunque sea privado
    monkeypatch.setenv("LAB_HOSTS", "lab-target")
    monkeypatch.setattr(utils, "resolve_ips", lambda host: ["172.18.0.3"])
    assert check_target("lab-target") == ["172.18.0.3"]
