"""
External Services Configuration
================================

This module contains configurations for external services (email, etc.).

IMPORTANT: Actual credentials should NEVER be hardcoded here.
They should be provided via environment variables (e.g., in .env files).

Environment variables to set:
  - EMAIL_BACKEND: Django email backend (console for dev, smtp for prod)
  - EMAIL_HOST: SMTP server hostname
  - EMAIL_PORT: SMTP server port
  - EMAIL_USE_TLS: Whether to use TLS
  - EMAIL_HOST_USER: SMTP username
  - EMAIL_HOST_PASSWORD: SMTP password (NEVER hardcode!)
  - DEFAULT_FROM_EMAIL: Sender email address
  - FRONTEND_URL: Frontend application URL for links
  - PLATFORM_NAME: Name of the platform/application
  - SUPPORT_EMAIL: Support contact email address
"""

from ..env import get_env

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================
# Email Configuration - Default to console backend (safe for development)
# Production will override this
EMAIL_BACKEND = get_env(
    "EMAIL_BACKEND",
    default="django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = get_env("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = get_env("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = get_env(
  "EMAIL_USE_TLS",
  default=True,
  cast=lambda v: str(v).lower() in ("true", "1", "yes", "on"),
)
EMAIL_HOST_USER = get_env("EMAIL_HOST_USER", default="benjaminkaranja8393@gmail.com")
EMAIL_HOST_PASSWORD = get_env("EMAIL_HOST_PASSWORD", default="usxp hdoy fjfq pdmm")
DEFAULT_FROM_EMAIL = get_env("DEFAULT_FROM_EMAIL", default="noreply@example.com")

