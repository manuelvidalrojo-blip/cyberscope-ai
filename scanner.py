"""
scanner.py
----------
Módulo de escaneo de infraestructura externa.

Responsabilidades (fase 2):
- Resolución DNS (A, MX, TXT, NS, CNAME)
- Escaneo de puertos comunes (80, 443, 21, 22, 25, 3389…)
- Detección de tecnologías expuestas (banner grabbing básico)
- Consulta a servicios de inteligencia pasiva (Shodan, Censys, etc.)
"""


def run_scan(domain: str) -> dict:
    """
    Ejecuta el escaneo completo para un dominio.

    Args:
        domain: Dominio objetivo sin esquema (ej. 'ejemplo.com').

    Returns:
        Diccionario con resultados del escaneo.
    """
    # TODO: implementar en fase 2
    raise NotImplementedError("scanner.run_scan no implementado aún.")
