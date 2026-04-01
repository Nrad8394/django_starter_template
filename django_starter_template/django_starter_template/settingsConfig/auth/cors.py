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