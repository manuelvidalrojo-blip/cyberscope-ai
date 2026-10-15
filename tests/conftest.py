"""Configuración común de las pruebas: sin red real y base de datos temporal."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture
def public_dns(monkeypatch):
    """Simula que cualquier dominio resuelve a una IP pública de documentación."""
    from modules import utils
    monkeypatch.setattr(utils, "resolve_ips", lambda host: ["93.184.216.34"])


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    """Base de datos SQLite aislada para cada prueba y hashing rápido."""
    from modules import auth, storage
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setattr(auth, "ITERATIONS", 1_000)
    storage.init_db()
    return tmp_path


@pytest.fixture
def sample_analysis():
    """Análisis completo de ejemplo (sin red) para scoring, informes e IA."""
    from modules.scoring import calculate_global_score

    scan = {"domain": "ejemplo.com", "http_status": 301, "https_status": 200, "uses_https": True,
            "redirects_to_https": True, "technologies": ["Server: nginx/1.18.0"],
            "version_disclosure": ["Server"], "error": None}
    headers = {"domain": "ejemplo.com", "headers_found": {
        "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": None,
        "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": None, "Permissions-Policy": None},
        "missing_headers": ["Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"],
        "security_score_headers": 50, "recommendations": ["Define una política 'Content-Security-Policy' ..."],
        "error": None}
    dns = {"a_records": ["93.184.216.34"], "aaaa_records": [], "mx_records": ["10 mail.ejemplo.com"],
           "ns_records": ["ns1.ejemplo.com"], "txt_records": ["v=spf1 -all"], "spf_found": True,
           "spf_record": "v=spf1 -all", "spf_all": "-all", "dmarc_found": True,
           "dmarc_record": "v=DMARC1; p=none", "dmarc_policy": "none", "error": None}
    tls = {"trusted": True, "issuer": "Let's Encrypt · R11", "subject": "ejemplo.com", "not_before": "2026-09-01",
           "not_after": "2026-11-30", "days_left": 46, "san": ["ejemplo.com"], "tls_version": "TLSv1.3",
           "cipher": "TLS_AES_256_GCM_SHA384", "secure_version": True, "expiring_soon": False, "error": None}
    exposure = {"hosts": [], "open_ports": [80, 443, 3306], "risky_ports": [{"port": 3306, "service": "MySQL"}],
                "vulns": [], "source": "Shodan InternetDB", "error": None}
    subdomains = {"subdomains": ["www.ejemplo.com"], "total": 1, "truncated": False, "source": "crt.sh", "error": None}
    return {
        "domain": "ejemplo.com", "ips": ["93.184.216.34"], "timestamp": "2026-10-15T10:00:00+00:00",
        "duration_s": 5.0, "scan": scan, "headers": headers, "dns": dns, "tls": tls,
        "exposure": exposure, "subdomains": subdomains,
        "score": calculate_global_score(scan, headers, dns, tls, exposure),
    }
