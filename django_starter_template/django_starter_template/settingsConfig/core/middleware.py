"""
Middleware Stack Configuration
================================

Defines the ordered list of middleware classes applied to every HTTP
request and response. Order matters — middleware is applied top-to-bottom
on the request path and bottom-to-top on the response path.

Layer-by-layer breakdown:

1. ``CorsMiddleware`` (corsheaders) — **must be first** so CORS
   preflight responses are returned before any other processing occurs.
2. ``SecurityMiddleware`` — adds HTTPS redirects, HSTS headers, and
   content-type sniffing protection in production.
3. ``SessionMiddleware`` — enables cookie-based sessions (used by
   Django admin and allauth registration flows even when the API itself
   is stateless).
4. ``CommonMiddleware`` — normalises URL trailing slashes and sets the
   ``Content-Length`` header.
5. ``CsrfViewMiddleware`` — enforces CSRF token validation on unsafe
   methods for session-authenticated views.
6. ``APICSRFMiddleware`` (custom) — selectively disables CSRF for JWT-
   authenticated API paths where cookie-based CSRF is irrelevant.
7. ``AuthenticationMiddleware`` — attaches ``request.user`` by reading
   the session (``AnonymousUser`` for token-only requests; the JWT
   authentication happens inside DRF, not here).
8. ``OTPMiddleware`` (django-otp) — annotates authenticated users with
   their OTP device status, enabling MFA enforcement per-view.
9. ``CurrentUserMiddleware`` (custom) — stores the current user in
   thread-local storage for audit field auto-population in models.
10. ``LoginSecurityMiddleware`` (custom) — enforces account lockout
    policies and tracks failed login attempts.
11. ``SessionActivityMiddleware`` (custom) — updates the user's last-
    seen timestamp and detects expired/idle sessions.
12. ``RateLimitMiddleware`` (security app) — applies per-IP and per-user
    rate limits before the view is reached.
13. ``AuditLogMiddleware`` (security app) — records all mutating API
    calls to the audit log.
14. ``AccountMiddleware`` (allauth) — required by allauth for headless
    and MFA flows.
15. ``MessageMiddleware`` — enables flash messages (used by admin and
    allauth HTML error pages).
16. ``XFrameOptionsMiddleware`` — sets the ``X-Frame-Options`` header
    to prevent clickjacking.
17. ``RequestTracingMiddleware`` (custom) — assigns a unique request ID
    to each request for cross-service log correlation.
18. ``PerformanceMiddleware`` (custom) — logs slow requests above a
    configurable threshold.
19. ``ErrorHandlingMiddleware`` (custom) — catches unhandled exceptions
    and returns structured JSON error responses instead of HTML 500
    pages.
"""

# Middleware stack - Consistent across all environments
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "apps.core.middleware.APICSRFMiddleware",  # Custom CSRF middleware for API
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "apps.core.middleware.CurrentUserMiddleware",  # Set current user in thread locals for audit fields
    "apps.accounts.middleware.LoginSecurityMiddleware",  # Login security enforcement
    "apps.accounts.middleware.SessionActivityMiddleware",  # Track session activity
    "apps.security.middleware.RateLimitMiddleware",  # Rate limiting
    "apps.security.middleware.AuditLogMiddleware",  # Audit logging
    "allauth.account.middleware.AccountMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.RequestTracingMiddleware",
    "apps.core.middleware.PerformanceMiddleware",
    "apps.core.middleware.ErrorHandlingMiddleware",
]