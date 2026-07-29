"""
Middleware Stack Configuration
================================

Middleware nests. The first entry is the outermost layer: it sees the request
first and the response last. Two consequences drive the ordering below.

*Anything that must run even when a later layer fails goes near the top.*
That is why request-id assignment, timing and the error envelope are the
first three: an exception in authentication still gets an id, a duration and
a JSON response.

*Anything that depends on work an earlier layer did must come after it.*
``CurrentUserMiddleware`` needs ``request.user``, so it must follow
``AuthenticationMiddleware``.

The stack below is the minimum that works. Custom entries are commented out
rather than deleted so enabling one is a single-line change, and each carries
the reason you might not want it.
"""

MIDDLEWARE = [
    # --- Outermost: observability and cross-origin -----------------------
    # CorsMiddleware must precede CommonMiddleware. CommonMiddleware issues
    # redirects (APPEND_SLASH), and a redirect without CORS headers fails the
    # browser's preflight — presenting as an inscrutable "CORS error" on a
    # request that was really just missing a trailing slash.
    "corsheaders.middleware.CorsMiddleware",
    "apps.core.middleware.RequestIDMiddleware",
    "apps.core.middleware.RequestTimingMiddleware",
    # Returns the API error envelope for exceptions raised outside DRF's
    # reach. Must wrap everything below it. No-ops when DEBUG is on.
    "apps.core.middleware.APIErrorEnvelopeMiddleware",
    # --- Django core ------------------------------------------------------
    "django.middleware.security.SecurityMiddleware",
    # WhiteNoise serves static files straight from the app process, and must
    # sit immediately after SecurityMiddleware.
    #
    # Enabled, not commented out. STORAGES already selects
    # CompressedManifestStaticFilesStorage whenever DEBUG is off, and
    # whitenoise is a declared dependency — but with the middleware disabled
    # nothing served those files. With DEBUG=False Django's own staticfiles
    # view switches off too, so the admin rendered unstyled in exactly the
    # environment where nobody is watching the console for 404s.
    #
    # Harmless in front of a CDN or nginx: those intercept /static/ before
    # the request reaches Django, so this only ever handles what they do not.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # CSRF applies to the session-authenticated surface: the admin, and
    # allauth's HTML flows. The JWT API is stateless, sends no cookie
    # credential, and is therefore not CSRF-exposed — DRF also exempts any
    # view whose authentication is not session-based, so no custom
    # "exempt /api/" middleware is needed. If you switch the API to cookie
    # auth, CSRF becomes load-bearing again; do not disable it then.
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Requires `django_otp` in INSTALLED_APPS. Remove both together.
    "django_otp.middleware.OTPMiddleware",
    # Required by allauth >= 0.56.
    "allauth.account.middleware.AccountMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # --- Optional project middleware --------------------------------------
    # Thread-local current user for model-layer audit fields. Off by default;
    # BaseModelViewSet passes the user explicitly instead. Read the class
    # docstring before enabling — it is empty in Celery tasks and management
    # commands, which is how audit fields quietly end up NULL.
    # "apps.core.middleware.CurrentUserMiddleware",
    #
    # From the optional `apps.security` app (enable the app first):
    # "apps.security.middleware.RateLimitMiddleware",
    # "apps.security.middleware.AuditLogMiddleware",
]

#: Requests slower than this are logged at WARNING by RequestTimingMiddleware.
#: Tighten it per environment; a threshold nothing ever crosses is a threshold
#: that teaches you nothing.
SLOW_REQUEST_THRESHOLD_SECONDS = 1.0

#: Path prefix treated as "the API" by APIErrorEnvelopeMiddleware.
API_PATH_PREFIX = "/api/"
