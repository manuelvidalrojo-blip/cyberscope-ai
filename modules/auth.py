"""
auth.py
-------
Autenticación, roles y límites de uso.

· Contraseñas con PBKDF2-HMAC-SHA256 (600.000 iteraciones, sal aleatoria de
  16 bytes) de la librería estándar; nunca se guardan en claro.
· Comparación en tiempo constante (hmac.compare_digest).
· Bloqueo temporal tras MAX_FAILED intentos fallidos en LOCK_MINUTES.
· Mensaje de error genérico: no revela si el usuario existe.
· Roles: 'admin' (gestiona usuarios, ve todo el historial y la auditoría)
  y 'analyst' (analiza y ve solo su propio historial).
· Límite de análisis por usuario y ventana de tiempo (anti-abuso).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from datetime import timedelta

from modules import storage

ITERATIONS = 600_000
MAX_FAILED = 5
LOCK_MINUTES = 15
MIN_PASSWORD_LENGTH = 12
ROLES = ("admin", "analyst")

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{3,32}$")

GENERIC_LOGIN_ERROR = "Usuario o contraseña incorrectos."


class AuthError(ValueError):
    """Error de validación con mensaje apto para el usuario."""


# ── Contraseñas ────────────────────────────────────────────────────────────────

def hash_password(password: str, iterations: int | None = None) -> str:
    iterations = iterations or ITERATIONS
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt, digest = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _unb64(salt), int(iterations))
        return hmac.compare_digest(candidate, _unb64(digest))
    except (ValueError, TypeError):
        return False


def validate_password(password: str) -> None:
    """Política mínima: 12 caracteres con letras y números."""
    if len(password or "") < MIN_PASSWORD_LENGTH:
        raise AuthError(f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres.")
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise AuthError("La contraseña debe combinar letras y números.")


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# Hash ficticio para igualar el tiempo de respuesta cuando el usuario no existe
_DUMMY_HASH = hash_password("cyberscope-dummy-password-0")


# ── Usuarios ───────────────────────────────────────────────────────────────────

def create_user(username: str, password: str, role: str = "analyst") -> None:
    if not _USERNAME_RE.match(username or ""):
        raise AuthError("El usuario debe tener 3-32 caracteres: letras, números, '.', '_' o '-'.")
    if role not in ROLES:
        raise AuthError("Rol no válido.")
    validate_password(password)
    with storage.connect() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            raise AuthError("Ese usuario ya existe.")
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, storage.iso(storage.now_utc())),
        )


def list_users() -> list[dict]:
    with storage.connect() as conn:
        rows = conn.execute("SELECT username, role, active, created_at, last_login FROM users ORDER BY username")
        return [dict(r) for r in rows]


def set_active(username: str, active: bool) -> None:
    with storage.connect() as conn:
        conn.execute("UPDATE users SET active = ? WHERE username = ?", (1 if active else 0, username))


def count_users() -> int:
    with storage.connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def bootstrap_admin_from_env() -> str | None:
    """
    Si no hay ningún usuario, crea el administrador inicial a partir de
    CYBERSCOPE_ADMIN_USER y CYBERSCOPE_ADMIN_PASSWORD (variables de entorno).
    """
    if count_users() > 0:
        return None
    username = os.getenv("CYBERSCOPE_ADMIN_USER", "").strip()
    password = os.getenv("CYBERSCOPE_ADMIN_PASSWORD", "")
    if not username or not password:
        return None
    create_user(username, password, role="admin")
    storage.audit("user_bootstrap", username, "Administrador inicial creado desde variables de entorno")
    return username


# ── Login ──────────────────────────────────────────────────────────────────────

def is_locked(username: str) -> bool:
    since = storage.iso(storage.now_utc() - timedelta(minutes=LOCK_MINUTES))
    with storage.connect() as conn:
        rows = conn.execute(
            "SELECT success FROM login_attempts WHERE username = ? AND ts >= ? ORDER BY id DESC LIMIT ?",
            (username, since, MAX_FAILED),
        ).fetchall()
    # Bloqueado si los últimos MAX_FAILED intentos dentro de la ventana fallaron todos
    return len(rows) >= MAX_FAILED and all(r["success"] == 0 for r in rows)


def authenticate(username: str, password: str, ip: str | None = None) -> dict:
    """
    Comprueba credenciales.

    Returns:
        dict con username y role si son correctas.
    Raises:
        AuthError con un mensaje genérico (o de bloqueo).
    """
    username = (username or "").strip()
    if not username or not password:
        raise AuthError(GENERIC_LOGIN_ERROR)

    if is_locked(username):
        storage.audit("login_blocked", username, "Intento durante bloqueo temporal", ip)
        raise AuthError(f"Demasiados intentos fallidos. Espera {LOCK_MINUTES} minutos e inténtalo de nuevo.")

    with storage.connect() as conn:
        row = conn.execute(
            "SELECT username, password_hash, role, active FROM users WHERE username = ?", (username,)
        ).fetchone()

    ok = verify_password(password, row["password_hash"] if row else _DUMMY_HASH)
    ok = ok and row is not None and bool(row["active"])

    with storage.connect() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, ip, success, ts) VALUES (?, ?, ?, ?)",
            (username, ip, 1 if ok else 0, storage.iso(storage.now_utc())),
        )
        if ok:
            conn.execute("UPDATE users SET last_login = ? WHERE username = ?", (storage.iso(storage.now_utc()), row["username"]))

    storage.audit("login_ok" if ok else "login_failed", username, None, ip)
    if not ok:
        raise AuthError(GENERIC_LOGIN_ERROR)
    return {"username": row["username"], "role": row["role"]}


# ── Límite de análisis ─────────────────────────────────────────────────────────

def rate_limit_status(username: str) -> tuple[bool, int, int]:
    """
    Returns:
        (permitido, análisis usados en la ventana, máximo permitido)
    """
    max_req = int(os.getenv("RATE_LIMIT_ANALYSES", "10"))
    window = int(os.getenv("RATE_LIMIT_WINDOW_MIN", "10"))
    since = storage.now_utc() - timedelta(minutes=window)
    used = storage.count_events(username, "analysis_requested", since)
    return used < max_req, used, max_req
