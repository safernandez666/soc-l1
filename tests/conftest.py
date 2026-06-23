"""Configuración global de pytest.

Objetivo nº1: la suite NUNCA debe disparar side-effects reales (mail, tickets InvGate,
escritura en la state.db de prod), aunque se corra por error en el box de producción.

Por qué hace falta ser agresivo: el webhook responde 202 y procesa el pipeline en una
**tarea background** que sobrevive al teardown del test. Si la hermeticidad fuera solo
por-test, esa tarea reconstruye la config después del teardown, lee el `.env` real y
termina escribiendo en prod + mandando mails + creando tickets. Caso real observado.

Defensa en dos capas:

  1) Guardas vía `os.environ` (precedencia sobre el `.env` file en pydantic-settings):
     dejan inertes los endpoints con efecto externo para TODO el proceso de test. Esta es
     la capa que GARANTIZA que no haya spam, pase lo que pase con el `.env`.

  2) `env_file=None` reseteado antes de CADA test (sin restaurar): hermeticidad de los
     valores de config, y resetea la polución de algún test que reactive la lectura.

Nota: hay 9 tests que fallan en la suite COMPLETA por un bug de orden/contaminación
preexistente (no relacionado con esto); fallan igual con o sin estos cambios.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from src.config import LdapConfig, Settings, get_settings

# --- Capa 1: guardas os.environ (corren al importar el conftest, antes de los tests) ---
os.environ["SMTP_HOST"] = ""          # mailer hace skip si no hay host → sin mails
os.environ["HOST_INVGATE"] = ""       # sin cliente InvGate → sin tickets
os.environ["STATE_DB_PATH"] = os.path.join(  # nunca la state.db de prod
    tempfile.gettempdir(), "soc-l1-pytest-state.db"
)


def _disable_dotenv() -> None:
    Settings.model_config["env_file"] = None
    LdapConfig.model_config["env_file"] = None
    get_settings.cache_clear()


# --- Capa 2: env_file=None (al importar + antes de cada test) ---
_disable_dotenv()


@pytest.fixture(autouse=True)
def _isolate_settings_from_dotenv() -> None:
    """Antes de CADA test: env_file=None + cache limpio. NO restaura (las tareas
    background del webhook corren tras el teardown y deben seguir viendo None)."""
    _disable_dotenv()
    yield
    get_settings.cache_clear()
