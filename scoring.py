"""
scoring.py
----------
Módulo de puntuación y clasificación de riesgo.

Responsabilidades (fase 3):
- Recibe los resultados de scanner.py y headers.py
- Asigna pesos y penalizaciones por hallazgo
- Calcula una puntuación global (0–100) y una letra de riesgo (A–F)
- Genera una lista priorizada de hallazgos (Critical / High / Medium / Low / Info)
"""


def calculate_score(scan_results: dict, header_results: dict) -> dict:
    """
    Calcula la puntuación de riesgo global del dominio.

    Args:
        scan_results: Salida de scanner.run_scan().
        header_results: Salida de headers.analyze_headers().

    Returns:
        Diccionario con puntuación, letra de riesgo y hallazgos priorizados.
    """
    # TODO: implementar en fase 3
    raise NotImplementedError("scoring.calculate_score no implementado aún.")
