"""
Django REST Framework Configuration
====================================

Applies to every API view unless a view overrides it.

Key decisions
-------------

**Authentication: JWT only.** No ``SessionAuthentication`` in the default
list. Mixing them means the API is reachable with a session cookie, which
re-introduces CSRF as an attack surface on every endpoint and makes the
security model depend on which credential the browser happened to send.
Session auth stays enabled for the Django admin, which is separate.

**Permissions: deny by default.** ``IsAuthenticated`` +
``FullDjangoModelPermissions`` means a new view is locked until someone says
otherwise. The alternative — a permissive default with per-view lockdown —
fails open: forget the decorator and the endpoint is public. Forgetting it
here produces a 403 in development, which is noticed immediately.

Note this is stricter than DRF's own ``DjangoModelPermissions``, which
deliberately leaves ``GET`` unguarded. See
``apps.core.permissions.FullDjangoModelPermissions``.

**Errors: one envelope, always.** ``EXCEPTION_HANDLER`` points at
``apps.core.exceptions.api_exception_handler``. Read that module before
changing it — it exists because the alternative (six different error shapes,
depending on which exception fired) pushes the cost onto every client. This
is the single highest-leverage setting in this file.

**Browsable API: development only.** ``BrowsableAPIRenderer`` renders every
response through a Django template, which is slow, and it exposes an HTML
form that will happily POST to any endpoint using the caller's credentials.
``production.py`` strips it.

**Throttling: on by default.** Rates are generous and env-tunable. An API
with no throttle at all has no floor under a credential-stuffing or scraping
run. Tighten ``anon`` in particular for public endpoints.

Reference: https://www.django-rest-framework.org/api-guide/settings/
"""

from ..env import get_env, get_int

REST_FRAMEWORK = {
    # --- Authentication ---------------------------------------------------
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ],
    # --- Authorization ----------------------------------------------------
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
        "apps.core.permissions.FullDjangoModelPermissions",
    ],
    # --- Content negotiation ---------------------------------------------
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",  # removed in production.py
    ],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
        "rest_framework.parsers.MultiPartParser",
        "rest_framework.parsers.FormParser",
    ],
    # --- Filtering --------------------------------------------------------
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    # --- Pagination -------------------------------------------------------
    "DEFAULT_PAGINATION_CLASS": "apps.core.pagination.StandardResultsSetPagination",
    "PAGE_SIZE": get_int("DRF_PAGE_SIZE", default=20),
    # --- Errors -----------------------------------------------------------
    # See apps/core/exceptions.py. Everything a client sees for a non-2xx
    # response is shaped here.
    "EXCEPTION_HANDLER": "apps.core.exceptions.api_exception_handler",
    # --- Throttling -------------------------------------------------------
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.AnonRateThrottle",
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "anon": get_env("DRF_THROTTLE_ANON_RATE", default="100/hour"),
        "user": get_env("DRF_THROTTLE_USER_RATE", default="2000/hour"),
        # Scoped throttles. Apply with `throttle_scope = "burst"` on a view.
        # Add your own scopes here rather than hard-coding rates in views.
        "burst": get_env("DRF_THROTTLE_BURST_RATE", default="30/minute"),
        "login": get_env("DRF_THROTTLE_LOGIN_RATE", default="10/minute"),
    },
    # --- Schema -----------------------------------------------------------
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    # --- Dates ------------------------------------------------------------
    # ISO 8601 in, ISO 8601 out. Leaving this to Django's locale-aware
    # formatting means the API's date format changes with LANGUAGE_CODE,
    # which is a genuinely surprising way to break a client.
    "DATETIME_FORMAT": "iso-8601",
    "DATE_FORMAT": "iso-8601",
    "TIME_FORMAT": "iso-8601",
}
