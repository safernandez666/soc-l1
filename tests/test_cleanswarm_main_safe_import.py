"""Importing cleanswarm.__main__ must not raise SystemExit."""
import importlib


def test_importing_main_does_not_exit():
    # If __main__ runs SystemExit at import, this raises.
    importlib.import_module("src.cleanswarm.__main__")
