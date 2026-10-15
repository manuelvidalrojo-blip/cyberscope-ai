"""Autenticación y roles (RF-16), límite de uso (RNF-06), historial (RF-15) y auditoría (RNF-05)."""

import pytest

from modules import auth, storage
from modules.auth import AuthError


def test_pr28_password_hashing():
    """PR-28 · RF-16: las contraseñas se guardan con PBKDF2 y sal; nunca en claro."""
    h1 = auth.hash_password("ClaveSegura2026", iterations=1000)
    h2 = auth.hash_password("ClaveSegura2026", iterations=1000)
    assert h1 != h2                                   # sal distinta
    assert "ClaveSegura2026" not in h1
    assert auth.verify_password("ClaveSegura2026", h1)
    assert not auth.verify_password("otra", h1)
    assert not auth.verify_password("x", "formato-roto")


@pytest.mark.parametrize("password", ["corta1", "sololetrasmuylarga", "123456789012345"])
def test_pr29_password_policy(temp_db, password):
    """PR-29 · RF-16: se rechazan contraseñas cortas o sin letras y números."""
    with pytest.raises(AuthError):
        auth.create_user("usuario1", password)


def test_pr30_login_ok_and_generic_error(temp_db):
    """PR-30 · RF-16: login correcto devuelve el rol; usuario inexistente y clave errónea dan el MISMO mensaje."""
    auth.create_user("analista", "ClaveSegura2026", "analyst")
    assert auth.authenticate("analista", "ClaveSegura2026") == {"username": "analista", "role": "analyst"}

    with pytest.raises(AuthError) as wrong_pass:
        auth.authenticate("analista", "Incorrecta2026")
    with pytest.raises(AuthError) as no_user:
        auth.authenticate("fantasma", "Incorrecta2026")
    assert str(wrong_pass.value) == str(no_user.value) == auth.GENERIC_LOGIN_ERROR


def test_pr31_lockout_after_failed_attempts(temp_db):
    """PR-31 · RF-16: tras 5 fallos la cuenta se bloquea temporalmente, incluso con la clave correcta."""
    auth.create_user("victima", "ClaveSegura2026")
    for _ in range(auth.MAX_FAILED):
        with pytest.raises(AuthError):
            auth.authenticate("victima", "Incorrecta2026", ip="203.0.113.7")
    with pytest.raises(AuthError, match="Demasiados intentos"):
        auth.authenticate("victima", "ClaveSegura2026")
    events = [e["event"] for e in storage.list_audit()]
    assert events.count("login_failed") == auth.MAX_FAILED and "login_blocked" in events


def test_pr32_inactive_user_cannot_login(temp_db):
    """PR-32 · RF-16: un usuario desactivado por el administrador no puede entrar."""
    auth.create_user("baja", "ClaveSegura2026")
    auth.set_active("baja", False)
    with pytest.raises(AuthError):
        auth.authenticate("baja", "ClaveSegura2026")


def test_pr33_bootstrap_admin(temp_db, monkeypatch):
    """PR-33 · RF-16: el administrador inicial se crea desde variables de entorno solo si no hay usuarios."""
    monkeypatch.setenv("CYBERSCOPE_ADMIN_USER", "admin")
    monkeypatch.setenv("CYBERSCOPE_ADMIN_PASSWORD", "AdminSegura2026")
    assert auth.bootstrap_admin_from_env() == "admin"
    assert auth.bootstrap_admin_from_env() is None          # segunda vez no hace nada
    assert auth.authenticate("admin", "AdminSegura2026")["role"] == "admin"


def test_pr34_rate_limit(temp_db, monkeypatch):
    """PR-34 · RNF-06: al superar N análisis en la ventana, se deniegan los siguientes."""
    monkeypatch.setenv("RATE_LIMIT_ANALYSES", "3")
    for _ in range(3):
        assert auth.rate_limit_status("ana")[0] is True
        storage.audit("analysis_requested", "ana", "ejemplo.com")
    allowed, used, maximum = auth.rate_limit_status("ana")
    assert (allowed, used, maximum) == (False, 3, 3)
    assert auth.rate_limit_status("otro")[0] is True         # el límite es por usuario


def test_pr35_history_and_ownership(temp_db, sample_analysis):
    """PR-35 · RF-15: el historial guarda los análisis y un analista no puede ver los de otro."""
    id_ana = storage.save_analysis("ana", sample_analysis)
    storage.save_analysis("luis", sample_analysis)

    assert len(storage.list_analyses(username="ana")) == 1
    assert len(storage.list_analyses(username=None)) == 2      # vista de administrador
    assert storage.get_analysis(id_ana, username="ana")["domain"] == "ejemplo.com"
    assert storage.get_analysis(id_ana, username="luis") is None


def test_pr36_sql_injection_is_harmless(temp_db, sample_analysis):
    """PR-36 · RNF-09: las consultas parametrizadas neutralizan intentos de inyección SQL."""
    storage.save_analysis("ana", sample_analysis)
    assert storage.list_analyses(username="ana' OR '1'='1") == []
    with pytest.raises(AuthError):
        auth.authenticate("admin' --", "loquesea12345")


def test_pr37_audit_retention(temp_db, monkeypatch):
    """PR-37 · RNF-05: los registros de auditoría (con IP) se purgan pasada la retención."""
    with storage.connect() as conn:
        conn.execute("INSERT INTO audit_log (ts, username, event, ip) VALUES ('2020-01-01T00:00:00+00:00', 'x', 'login_ok', '1.2.3.4')")
    storage.audit("login_ok", "y", ip="5.6.7.8")
    monkeypatch.setenv("AUDIT_RETENTION_DAYS", "90")
    assert storage.purge_old_records() == 1
    assert [e["username"] for e in storage.list_audit()] == ["y"]
