"""Configuración global de pytest.

Aísla los tests del `.env` real de producción: pydantic-settings, por defecto,
lee `env_file=".env"` al construir Settings/LdapConfig, así que valores de prod
(p.ej. DRY_RUN_MODE=true o la config LDAP) se filtraban y rompían los tests que
verifican el comportamiento con config ausente. El fixture autouse desactiva la
lectura del archivo para toda la sesión de test.
"""
from __future__ import annotations

import pytest

from src.config import LdapConfig, Settings


@pytest.fixture(autouse=True)
def _isolate_settings_from_dotenv(monkeypatch: pytest.MonkeyPatch) -> None:
    """No leer el .env real durante los tests (hermeticidad)."""
    monkeypatch.setitem(Settings.model_config, "env_file", None)
    monkeypatch.setitem(LdapConfig.model_config, "env_file", None)
