"""
Gestión de usuarios desde la línea de comandos.

    python scripts/manage_users.py add <usuario> --role analyst
    python scripts/manage_users.py list
    python scripts/manage_users.py disable <usuario>

La contraseña se pide por teclado (no queda en el historial de la shell).
En Docker:  docker compose exec app python scripts/manage_users.py list
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv  # noqa: E402

from modules import auth, storage  # noqa: E402


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Gestión de usuarios de CyberScope AI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="Crear usuario")
    add.add_argument("username")
    add.add_argument("--role", choices=auth.ROLES, default="analyst")
    sub.add_parser("list", help="Listar usuarios")
    for name in ("disable", "enable"):
        p = sub.add_parser(name, help=f"{name} usuario")
        p.add_argument("username")
    args = parser.parse_args()

    storage.init_db()

    if args.cmd == "add":
        password = getpass.getpass("Contraseña: ")
        if password != getpass.getpass("Repite la contraseña: "):
            print("Las contraseñas no coinciden.")
            return 1
        try:
            auth.create_user(args.username, password, args.role)
        except auth.AuthError as exc:
            print(f"Error: {exc}")
            return 1
        storage.audit("user_created", "cli", f"{args.username} ({args.role})")
        print(f"Usuario '{args.username}' creado con rol {args.role}.")
    elif args.cmd == "list":
        for u in auth.list_users():
            estado = "activo" if u["active"] else "inactivo"
            print(f"{u['username']:<20} {u['role']:<8} {estado:<9} último acceso: {u['last_login'] or '—'}")
    else:
        auth.set_active(args.username, args.cmd == "enable")
        storage.audit("user_toggled", "cli", f"{args.username} → {args.cmd}")
        print(f"Usuario '{args.username}' {'activado' if args.cmd == 'enable' else 'desactivado'}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
