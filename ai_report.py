"""
ai_report.py
------------
Módulo de generación de informes asistidos por IA.

Responsabilidades (fase 4):
- Recibe los resultados consolidados del análisis
- Genera un informe ejecutivo en lenguaje natural (español / inglés)
- Redacta recomendaciones de remediación concretas para cada hallazgo
- Exporta el informe en Markdown y PDF (carpeta reports/)
"""


def generate_report(score_results: dict, domain: str, output_format: str = "markdown") -> str:
    """
    Genera un informe ejecutivo de seguridad para el dominio analizado.

    Args:
        score_results: Salida de scoring.calculate_score().
        domain: Dominio analizado.
        output_format: 'markdown' o 'pdf'.

    Returns:
        Ruta del archivo de informe generado.
    """
    # TODO: implementar en fase 4
    raise NotImplementedError("ai_report.generate_report no implementado aún.")
