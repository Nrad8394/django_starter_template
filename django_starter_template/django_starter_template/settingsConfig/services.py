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

from decouple import config

# =============================================================================
# EMAIL CONFIGURATION
# =============================================================================
# Email Configuration - Default to console backend (safe for development)
# Production will override this
EMAIL_BACKEND = config(
    "EMAIL_BACKEND",
    default="django.core.mail.backends.smtp.EmailBackend",
)
EMAIL_HOST = config("EMAIL_HOST", default="smtp.gmail.com")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="benjaminkaranja8393@gmail.com")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="usxp hdoy fjfq pdmm")
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default="noreply@example.com")

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================
# Frontend URL for generating links in emails and API responses
FRONTEND_URL = config("FRONTEND_URL", default="https://logx.signox.co.ke")

# Platform/Brand name used in emails and UI
PLATFORM_NAME = config("PLATFORM_NAME", default="Smart School Management")

# Support contact email for user assistance
SUPPORT_EMAIL = config("SUPPORT_EMAIL", default="support@logx.com")

# Site/Platform name for API documentation
SITE_NAME = config("SITE_NAME", default="Smart School Management")

# Contact information for API documentation
CONTACT_NAME = config("CONTACT_NAME", default="Smart School Management Team")
CONTACT_EMAIL = config("CONTACT_EMAIL", default="support@logx.com")

# License information for API documentation
LICENSE_NAME = config("LICENSE_NAME", default="Proprietary")

