"""
Pruebas de los módulos de análisis con respuestas simuladas (sin red real).

Las pruebas de extremo a extremo contra un dominio real se documentan como
pruebas manuales en docs/plan_de_pruebas.md.
"""

from datetime import datetime, timezone

import pytest
import requests
from requests.structures import CaseInsensitiveDict

from modules import exposure, http_client, utils
from modules.dns_analyzer import parse_dmarc_policy, parse_spf_all
from modules.exposure import analyze_exposure, parse_internetdb
from modules.headers import analyze_security_headers
from modules.http_client import FetchError, FetchResult, safe_get
from modules.scanner import detect_technologies, scan_domain
from modules.subdomains import parse_crtsh
from modules.tls_analyzer import parse_certificate


# ── Utilidades de simulación ───────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status_code = status
        self.headers = CaseInsensitiveDict(headers or {})
        self.raw = self

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308) and "Location" in self.headers

    def read(self, *args, **kwargs):
        return b""

    def close(self):
        pass


def fetch(headers, status=200, url="https://ejemplo.com/"):
    return FetchResult(url=url, status_code=status, headers=CaseInsensitiveDict(headers))


# ── RF-02 · Conectividad ───────────────────────────────────────────────────────

def test_pr06_scan_http_redirects_to_https(monkeypatch, public_dns):
    """PR-06 · RF-02: se detecta HTTPS activo y la redirección HTTP → HTTPS."""
    routes = {
        "http://ejemplo.com": FakeResponse(301, {"Location": "https://ejemplo.com/"}),
        "https://ejemplo.com/": FakeResponse(200, {"Server": "nginx"}),
        "https://ejemplo.com": FakeResponse(200, {"Server": "nginx"}),
    }
    monkeypatch.setattr(http_client.requests, "get", lambda url, **kw: routes[url])
    result = scan_domain("ejemplo.com")
    assert result["http_status"] == 200
    assert result["https_status"] == 200
    assert result["uses_https"] is True
    assert result["redirects_to_https"] is True
    assert result["error"] is None


def test_pr07_network_errors_do_not_crash(monkeypatch, public_dns):
    """PR-07 · RNF-02: un dominio que no responde devuelve un error legible, sin excepción."""
    def boom(url, **kw):
        raise requests.exceptions.ConnectTimeout("timeout")
    monkeypatch.setattr(http_client.requests, "get", boom)
    result = scan_domain("ejemplo.com")
    assert result["http_status"] is None and result["https_status"] is None
    assert "Tiempo de espera" in result["error"]


def test_pr08_redirect_to_internal_ip_is_blocked(monkeypatch):
    """PR-08 · RNF-07: una redirección hacia una IP interna se corta (anti-SSRF en cada salto)."""
    monkeypatch.setattr(utils, "resolve_ips",
                        lambda host: ["127.0.0.1"] if host == "interno.ejemplo.com" else ["8.8.8.8"])
    monkeypatch.setattr(http_client.requests, "get",
                        lambda url, **kw: FakeResponse(302, {"Location": "http://interno.ejemplo.com/admin"}))
    with pytest.raises(FetchError, match="Redirección bloqueada"):
        safe_get("https://ejemplo.com")


def test_pr09_redirect_loop_is_limited(monkeypatch, public_dns):
    """PR-09 · RNF-02: un bucle de redirecciones se detiene tras el máximo permitido."""
    monkeypatch.setattr(http_client.requests, "get",
                        lambda url, **kw: FakeResponse(302, {"Location": "https://ejemplo.com/otra"}))
    with pytest.raises(FetchError, match="Demasiadas redirecciones"):
        safe_get("https://ejemplo.com")


def test_pr38_malformed_redirect_is_handled(monkeypatch, public_dns):
    """PR-38 · RNF-02: una cabecera Location malformada no tumba el análisis (antes: ValueError)."""
    monkeypatch.setattr(http_client.requests, "get",
                        lambda url, **kw: FakeResponse(302, {"Location": "http://[invalido/"}))
    with pytest.raises(FetchError, match="URL no válida"):
        safe_get("https://ejemplo.com")
    result = scan_domain("ejemplo.com")
    assert result["http_status"] is None and "URL no válida" in result["error"]


# ── RF-03 · Cabeceras ──────────────────────────────────────────────────────────

def test_pr10_headers_all_present():
    """PR-10 · RF-03: con las 6 cabeceras presentes la puntuación parcial es 100 y no hay recomendaciones."""
    full = {h: "valor" for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                                 "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]}
    result = analyze_security_headers("ejemplo.com", fetch(full))
    assert result["security_score_headers"] == 100
    assert result["missing_headers"] == []
    assert result["recommendations"] == []


def test_pr11_headers_missing_generate_recommendations():
    """PR-11 · RF-03 / RF-07: cada cabecera ausente genera su recomendación; la tabla 6→100 ... 0→0 se respeta."""
    result = analyze_security_headers("ejemplo.com", fetch({"x-frame-options": "DENY", "x-content-type-options": "nosniff"}))
    assert result["security_score_headers"] == 35          # 2 cabeceras
    assert len(result["missing_headers"]) == 4
    assert len(result["recommendations"]) == 4
    empty = analyze_security_headers("ejemplo.com", fetch({}))
    assert empty["security_score_headers"] == 0 and empty["risk_level_headers"] == "Alto"


# ── RF-17 · Tecnologías ────────────────────────────────────────────────────────

def test_pr12_detect_technologies_and_version_disclosure():
    """PR-12 · RF-17: se identifican tecnologías y las cabeceras que revelan versiones."""
    techs, disclosed = detect_technologies(CaseInsensitiveDict({
        "Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3",
        "CF-RAY": "abc", "Set-Cookie": "PHPSESSID=123; path=/",
    }))
    assert any("Apache/2.4.41" in t for t in techs)
    assert "Cloudflare (CDN)" in techs and "PHP" in techs
    assert disclosed == ["Server", "X-Powered-By"]


# ── RF-05 · SPF y DMARC ────────────────────────────────────────────────────────

@pytest.mark.parametrize("record, policy", [
    ("v=DMARC1; p=reject; rua=mailto:a@b.com", "reject"),
    ("v=DMARC1;p=quarantine", "quarantine"),
    ("v=DMARC1; sp=reject; p=none", "none"),
    ("v=DMARC1; p=loquesea", None),
])
def test_pr13_parse_dmarc_policy(record, policy):
    """PR-13 · RF-05: se extrae la política DMARC (p=) ignorando sp= y valores inválidos."""
    assert parse_dmarc_policy(record) == policy


@pytest.mark.parametrize("record, qualifier", [
    ("v=spf1 include:_spf.google.com -all", "-all"),
    ("v=spf1 mx ~all", "~all"),
    ("v=spf1 +all", "+all"),
    ("v=spf1 all", "+all"),
    ("v=spf1 mx", None),
])
def test_pr14_parse_spf_all(record, qualifier):
    """PR-14 · RF-05: se detecta el calificador final del SPF (incluido el peligroso +all)."""
    assert parse_spf_all(record) == qualifier


# ── RF-10 · TLS ────────────────────────────────────────────────────────────────

def test_pr15_parse_certificate():
    """PR-15 · RF-10: se calculan emisor, fechas, días restantes y aviso de caducidad próxima."""
    cert = {
        "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
        "subject": ((("commonName", "ejemplo.com"),),),
        "notBefore": "Sep  1 00:00:00 2026 GMT",
        "notAfter": "Oct 25 00:00:00 2026 GMT",
        "subjectAltName": (("DNS", "ejemplo.com"), ("DNS", "www.ejemplo.com")),
    }
    parsed = parse_certificate(cert, now=datetime(2026, 10, 15, tzinfo=timezone.utc))
    assert parsed["issuer"] == "Let's Encrypt · R11"
    assert parsed["not_after"] == "2026-10-25"
    assert parsed["days_left"] == 10
    assert parsed["expiring_soon"] is True
    assert parsed["san"] == ["ejemplo.com", "www.ejemplo.com"]


# ── RF-11 · Exposición (Shodan InternetDB) ─────────────────────────────────────

def test_pr16_internetdb_risky_ports(monkeypatch):
    """PR-16 · RF-11: se marcan los puertos peligrosos y se valida/filtra la respuesta externa."""
    monkeypatch.setattr(exposure, "query_internetdb", lambda ip: parse_internetdb(ip, {
        "ports": [443, 3389, "x", 99999], "vulns": ["CVE-2021-44228", "<script>"], "cpes": [], "hostnames": [],
    }))
    result = analyze_exposure(["8.8.8.8", "10.0.0.1"])     # la IP privada se descarta
    assert result["open_ports"] == [443, 3389]
    assert result["risky_ports"] == [{"port": 3389, "service": "Escritorio remoto (RDP)"}]
    assert result["vulns"] == ["CVE-2021-44228"]
    assert len(result["hosts"]) == 1


def test_pr17_internetdb_unavailable(monkeypatch):
    """PR-17 · RNF-02: si InternetDB no responde, se informa sin romper el análisis."""
    def down(ip):
        raise requests.exceptions.ConnectionError()
    monkeypatch.setattr(exposure, "query_internetdb", down)
    result = analyze_exposure(["8.8.8.8"])
    assert result["error"] and result["open_ports"] == []


# ── RF-13 · Subdominios ────────────────────────────────────────────────────────

def test_pr18_parse_crtsh():
    """PR-18 · RF-13: se extraen subdominios únicos del dominio, sin comodines ni nombres ajenos."""
    entries = [
        {"name_value": "www.ejemplo.com\n*.ejemplo.com"},
        {"name_value": "api.ejemplo.com"},
        {"name_value": "www.ejemplo.com"},
        {"name_value": "ejemplo.com.atacante.net"},
        {"name_value": "<img src=x>.ejemplo.com"},
        "basura",
    ]
    assert parse_crtsh("ejemplo.com", entries) == ["api.ejemplo.com", "www.ejemplo.com"]
