"""
Environment Variable Utilities
==============================

Provides the ``get_env`` helper used by every settings module to safely
retrieve and coerce environment variables.

Features:
- Reads values from ``os.environ`` with an optional default.
- Supports ``required=True`` to raise a clear ``Exception`` when a
  mandatory variable is absent (useful for production guard-rails).
- Accepts an arbitrary ``cast`` callable so callers can coerce strings
  to ``int``, ``bool``, comma-separated lists, etc. in one step.
- Raises an informative ``Exception`` when casting fails, preventing
  silent misconfiguration.

Usage example::

    from .env import get_env

    DEBUG = get_env("DJANGO_DEBUG", default=False,
                    cast=lambda v: v.lower() in ("true", "1", "yes"))
    DB_PORT = get_env("DB_PORT", default=5432, cast=int)
    SECRET_KEY = get_env("SECRET_KEY", required=True)
"""

import os


def get_env(variable_name, default=None, required=False, cast=str):
    value = os.environ.get(variable_name, default)

    if required and value is None:
        raise Exception(f"Missing required env variable: {variable_name}")

    try:
        return cast(value) if value is not None else value
    except Exception:
        raise Exception(f"Invalid value for {variable_name}")
