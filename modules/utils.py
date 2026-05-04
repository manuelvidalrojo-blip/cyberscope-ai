"""
utils.py
--------
Utilidades compartidas por el resto de módulos.
"""

import re


def validate_domain(domain: str) -> bool:
    """
    Valida que la cadena sea un dominio con formato correcto.

    Args:
        domain: Cadena a validar (sin esquema).

    Returns:
        True si el formato es válido, False en caso contrario.

    Examples:
        >>> validate_domain("ejemplo.com")
        True
        >>> validate_domain("http://ejemplo.com")
        False
        >>> validate_domain("no_es_un_dominio")
        False
    """
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def sanitize_domain(raw: str) -> str:
    """
    Limpia un input de usuario eliminando esquemas y barras finales.

    Args:
        raw: Input tal como lo introduce el usuario.

    Returns:
        Dominio limpio en minúsculas.

    Examples:
        >>> sanitize_domain("https://Ejemplo.com/")
        'ejemplo.com'
    """
    return (
        raw.strip()
        .lower()
        .removeprefix("http://")
        .removeprefix("https://")
        .rstrip("/")
    )


def save_report(content: str, filename: str, folder: str = "reports") -> str:
    """
    Guarda contenido de texto en la carpeta de informes.

    Args:
        content: Texto del informe.
        filename: Nombre del archivo (sin ruta).
        folder: Carpeta destino (por defecto 'reports').

    Returns:
        Ruta completa del archivo guardado.
    """
    import os

    os.makedirs(folder, exist_ok=True)
    filepath = os.path.join(folder, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath
