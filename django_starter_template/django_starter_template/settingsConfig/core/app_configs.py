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

