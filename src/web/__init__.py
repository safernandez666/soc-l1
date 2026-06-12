"""Paquete web: GUI de revisión (ZebraSecurity) servida en /ui.

Solo-lectura sobre state.db + login por cookie firmada (stdlib, sin deps nuevas).
No toca el pipeline: importa el router y se monta en main.py con app.include_router.
"""
from src.web.router import router

__all__ = ["router"]
