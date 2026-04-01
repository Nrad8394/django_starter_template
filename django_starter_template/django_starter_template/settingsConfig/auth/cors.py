"""
CORS and CSRF Configuration
============================

Configures ``django-cors-headers`` and Django's built-in CSRF protection
for API clients (typically a React/Vue/Next.js frontend).

CORS settings:
- ``CORS_ALLOWED_ORIGINS``: explicit origin whitelist for cross-origin
  requests. The development module overrides this with
  ``CORS_ALLOW_ALL_ORIGINS = True`` for convenience; production should
  set ``CORS_ALLOWED_ORIGINS`` via the ``CORS_ALLOWED_ORIGINS`` env var.
- ``CORS_ALLOW_CREDENTIALS = True``: required for the browser to send
  cookies and the ``Authorization`` header in cross-origin requests.
- ``CORS_ALLOW_HEADERS``: extends the CORS-safelisted headers to include
  ``x-csrftoken``, ``authorization``, and various proxy headers.
- ``CORS_EXPOSE_HEADERS``: tells the browser it may read ``content-type``
  and ``x-csrftoken`` from cross-origin responses.

CSRF settings:
- ``CSRF_TRUSTED_ORIGINS``: origins allowed to make unsafe (POST/PUT/…)
  requests. Keep in sync with ``CORS_ALLOWED_ORIGINS``.
- ``CSRF_COOKIE_HTTPONLY = False``: deliberately allows JavaScript to
  read the CSRF cookie so SPA clients can attach it as a header.
- ``CSRF_USE_SESSIONS = False``: stores the token in a cookie, not the
  session, which is required for stateless JWT-based APIs.

Reference:
  https://github.com/adamchainz/django-cors-headers
  https://docs.djangoproject.com/en/stable/ref/csrf/
"""

# CORS Settings
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost",
    "http://102.207.222.11",
]


CORS_ALLOW_CREDENTIALS = True

# CORS Headers for CSRF
CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
    "X-Requested-With",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "cache-control",
    "pragma",
]

# Expose headers to the frontend
CORS_EXPOSE_HEADERS = [
    "content-type",
    "x-csrftoken",
]

# CORS Methods
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

# CSRF Settings
CSRF_TRUSTED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

CSRF_COOKIE_NAME = "csrftoken"
CSRF_HEADER_NAME = "HTTP_X_CSRFTOKEN"
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript access to CSRF token
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_USE_SESSIONS = False