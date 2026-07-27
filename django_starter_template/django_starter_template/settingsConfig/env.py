"""
Environment Variable Utilities
==============================

Every settings module reads configuration through the helpers here rather than
touching ``os.environ`` directly. That gives one place to enforce type
coercion, required-ness, and "fail loudly on a typo" behaviour.

Design notes
------------

``get_env(name, default, required, cast)``
    The general-purpose reader. ``cast`` is applied only to values that came
    from the environment as *strings*; a non-string ``default`` is returned
    untouched.

    This matters. A naive implementation writes::

        return cast(value) if value is not None else value

    …and then ``get_env("DEBUG", default=False, cast=bool)`` returns
    ``bool(False) == False`` — correct by accident — while
    ``get_env("DEBUG", default=True, cast=bool)`` with ``DEBUG=False`` in the
    environment returns ``bool("False") == True``. Two separate footguns:
    ``bool()`` on a non-empty string is always ``True``, and casting an
    already-typed default is pointless work that can corrupt it. The typed
    helpers below exist so callers never reach for ``cast=bool`` at all.

``get_bool`` / ``get_int`` / ``get_list``
    Prefer these. They handle the string forms people actually put in
    ``.env`` files and raise ``ImproperlyConfigured`` (which Django reports
    cleanly at startup) rather than a bare ``Exception``.

Usage::

    from .env import get_env, get_bool, get_int, get_list

    SECRET_KEY = get_env("SECRET_KEY", required=True)
    DEBUG = get_bool("DEBUG", default=False)
    DB_PORT = get_int("DB_PORT", default=5432)
    ALLOWED_HOSTS = get_list("DJANGO_ALLOWED_HOSTS", default=["localhost"])
"""

import os

from django.core.exceptions import ImproperlyConfigured

#: Strings accepted as boolean true / false in environment variables.
TRUE_VALUES = frozenset({"1", "true", "yes", "y", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "n", "off", ""})

_MISSING = object()


def get_env(variable_name, default=None, required=False, cast=None):
    """
    Read ``variable_name`` from the environment.

    Parameters
    ----------
    default
        Returned when the variable is absent. Returned *as-is* — ``cast`` is
        never applied to it, so a typed default stays typed.
    required
        Raise ``ImproperlyConfigured`` when the variable is absent and no
        default was supplied.
    cast
        Callable applied to the raw string from the environment. ``None``
        means "leave it as a string".
    """
    raw = os.environ.get(variable_name, _MISSING)

    if raw is _MISSING:
        if required and default is None:
            raise ImproperlyConfigured(
                f"Missing required environment variable: {variable_name}"
            )
        return default

    if cast is None:
        return raw

    try:
        return cast(raw)
    except (TypeError, ValueError) as exc:
        raise ImproperlyConfigured(
            f"Invalid value for {variable_name}: {raw!r} ({exc})"
        ) from exc


def get_bool(variable_name, default=False, required=False):
    """
    Read a boolean.

    Accepts ``1/true/yes/y/on`` and ``0/false/no/n/off`` case-insensitively.
    An unrecognised value is an error, not a silent ``True`` — ``DEBUG=ture``
    should not ship a debug build to production.
    """
    raw = os.environ.get(variable_name, _MISSING)

    if raw is _MISSING:
        if required:
            raise ImproperlyConfigured(
                f"Missing required environment variable: {variable_name}"
            )
        return default

    normalized = str(raw).strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False

    accepted = sorted((TRUE_VALUES | FALSE_VALUES) - {""})
    raise ImproperlyConfigured(
        f"{variable_name}={raw!r} is not a recognised boolean. "
        f"Use one of: {', '.join(accepted)}."
    )


def get_int(variable_name, default=None, required=False):
    """Read an integer."""
    return get_env(variable_name, default=default, required=required, cast=int)


def get_list(variable_name, default=None, required=False, separator=","):
    """
    Read a separator-delimited list.

    Blank entries are dropped, so ``"a,,b,"`` yields ``["a", "b"]`` and an
    empty variable yields ``[]`` rather than ``[""]`` — the latter is a
    classic cause of ``ALLOWED_HOSTS`` accidentally containing an empty
    hostname.
    """
    raw = os.environ.get(variable_name, _MISSING)

    if raw is _MISSING:
        if required:
            raise ImproperlyConfigured(
                f"Missing required environment variable: {variable_name}"
            )
        return list(default) if default is not None else []

    return [part.strip() for part in str(raw).split(separator) if part.strip()]
