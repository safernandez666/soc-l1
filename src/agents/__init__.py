"""Runtime compartido de los agentes LLM.

`run_agent` centraliza la robustez de las llamadas al LLM: timeout por intento +
retry con backoff ante errores transitorios (rate limit, timeout, 5xx). Si agota
los reintentos re-lanza la excepción para que el caller (los wrappers `*_safely`
de main.py) decida el fallback, en vez de colgar el background task o descartar
la alerta por un 429 pasajero.
"""
from __future__ import annotations

import asyncio
import logging
import random

from agents import Runner

logger = logging.getLogger("soc-l1")

# Excepciones que vale la pena reintentar. asyncio.TimeoutError viene de wait_for;
# las de openai se agregan si el paquete está disponible (no es dependencia dura).
_TRANSIENT: tuple[type[BaseException], ...] = (asyncio.TimeoutError,)
try:  # pragma: no cover - depende del entorno
    from openai import (
        APIConnectionError,
        APITimeoutError,
        InternalServerError,
        RateLimitError,
    )

    _TRANSIENT = _TRANSIENT + (
        APIConnectionError,
        APITimeoutError,
        InternalServerError,
        RateLimitError,
    )
except Exception:  # noqa: BLE001 - si openai no expone estos símbolos, seguimos
    pass


async def run_agent(
    agent,
    *,
    timeout: float = 60.0,
    retries: int = 2,
    label: str = "agent",
    **kwargs,
):
    """Ejecuta Runner.run(agent, **kwargs) con timeout por intento + retry.

    timeout: segundos por intento (los agentes con tools necesitan más).
    retries: reintentos extra ante errores transitorios (total = retries + 1).
    label:   nombre para los logs.

    Re-lanza la última excepción si agota reintentos, o la excepción inmediata si
    no es transitoria (p.ej. MaxTurnsExceeded: reintentar quemaría tokens sin sentido).
    """
    last_exc: BaseException | None = None
    for attempt in range(retries + 1):
        try:
            return await asyncio.wait_for(Runner.run(agent, **kwargs), timeout=timeout)
        except _TRANSIENT as e:
            last_exc = e
            if attempt < retries:
                backoff = min(2.0**attempt, 8.0) + random.uniform(0, 0.5)
                logger.warning(
                    "%s: error transitorio (%s), retry %d/%d en %.1fs",
                    label, type(e).__name__, attempt + 1, retries, backoff,
                )
                await asyncio.sleep(backoff)
            else:
                logger.error("%s: agotados %d reintentos: %s", label, retries, e)
    assert last_exc is not None
    raise last_exc
