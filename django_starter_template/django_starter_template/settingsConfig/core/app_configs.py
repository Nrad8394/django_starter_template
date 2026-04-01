"""
Application Branding and Metadata
===================================

Loads site-wide configuration values from environment variables.
These constants are imported by other settings modules (e.g. the admin
jazzmin config and the Spectacular API docs) to keep branding consistent
across the whole application without hardcoding strings.

Variables:
- ``FRONTEND_URL``: Full base URL of the frontend (e.g.
  ``https://app.example.com``). Used when constructing absolute links
  in transactional emails (password reset, email verification, etc.).
- ``PLATFORM_NAME``: Human-readable name of the platform shown in
  email subjects, footers, and the admin "from" header.
- ``SUPPORT_EMAIL``: Support inbox address embedded in automated emails
  so users know who to contact.
- ``SITE_NAME``: Short application name used as the admin site title,
  API documentation title, and Jazzmin branding.
- ``CONTACT_NAME`` / ``CONTACT_EMAIL``: Contact details shown in the
  OpenAPI ``info.contact`` object (Swagger/ReDoc contact card).
- ``LICENSE_NAME``: License label shown in the OpenAPI ``info.license``
  object. Defaults to ``"Proprietary"``.

All values default to empty strings so the application starts cleanly
in development without a fully populated ``.env`` file; set them via
``.env`` or secret management before deploying to production.
"""

from ..env import get_env

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================
# Frontend URL for generating links in emails and API responses
FRONTEND_URL = get_env("FRONTEND_URL", default="")

# Platform/Brand name used in emails and UI
PLATFORM_NAME = get_env("PLATFORM_NAME", default="")

# Support contact email for user assistance
SUPPORT_EMAIL = get_env("SUPPORT_EMAIL", default="")

# Site/Platform name for API documentation
SITE_NAME = get_env("SITE_NAME", default="")

# Contact information for API documentation
CONTACT_NAME = get_env("CONTACT_NAME", default="")
CONTACT_EMAIL = get_env("CONTACT_EMAIL", default="")

# License information for API documentation
LICENSE_NAME = get_env("LICENSE_NAME", default="Proprietary")

