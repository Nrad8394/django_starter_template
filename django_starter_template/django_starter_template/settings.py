"""
Settings entry point.
=====================

`DJANGO_SETTINGS_MODULE` always points at THIS module (see `manage.py`,
`wsgi.py`, `asgi.py`). Which environment profile gets loaded is decided by a
separate variable, `DJANGO_ENV`:

    DJANGO_ENV=development   (default)
    DJANGO_ENV=test
    DJANGO_ENV=production

    $ DJANGO_ENV=production gunicorn django_starter_template.wsgi:application

Why a second variable instead of pointing DJANGO_SETTINGS_MODULE straight at
`settingsConfig.production`?
---------------------------------------------------------------------------
Both work. This template uses `DJANGO_ENV` because:

  * There is exactly one import path to remember. Tooling that hard-codes
    `DJANGO_SETTINGS_MODULE` (pytest-django, Celery, IDE run configs, the
    Docker entrypoint) never has to be kept in sync with the profile.
  * Misspelling the value fails loudly here rather than producing an
    `ImportError` deep inside Django's startup.

The trade-off: an extra indirection, and `python -c "import
settingsConfig.production"` is no longer how you inspect prod settings — use
`DJANGO_ENV=production python manage.py diffsettings` instead.

NOTE FOR TEMPLATE USERS
-----------------------
An earlier iteration of this file branched on the *value of
`DJANGO_SETTINGS_MODULE` itself*. That can never select anything but the
default: if the variable is set to `...settingsConfig.production`, Django
imports that module directly and this file never runs; if it is set to
`...settings` (the only case where this file runs), the comparison against
`...settingsConfig.production` is false. The result is a project that
silently runs development settings in production. Keep the two variables
distinct.
"""

import os

_ENV = os.environ.get("DJANGO_ENV", "development").strip().lower()

_VALID_ENVS = {"development", "test", "production"}

if _ENV not in _VALID_ENVS:
    raise ValueError(
        f"DJANGO_ENV={_ENV!r} is not recognised. "
        f"Expected one of: {', '.join(sorted(_VALID_ENVS))}."
    )

if _ENV == "production":
    from .settingsConfig.production import *  # noqa: F401,F403
elif _ENV == "test":
    from .settingsConfig.test import *  # noqa: F401,F403
else:
    from .settingsConfig.development import *  # noqa: F401,F403

# Expose the resolved profile so health checks / the admin footer / logs can
# report which settings are actually live.
DJANGO_ENV = _ENV
