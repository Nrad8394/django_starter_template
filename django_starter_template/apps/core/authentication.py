"""
Custom authentication classes for the core app
"""
from rest_framework.authentication import SessionAuthentication


class CSRFExemptSessionAuthentication(SessionAuthentication):
    """
    Session authentication that exempts CSRF validation for API endpoints.

    This is useful for API-only endpoints where CSRF protection is not needed
    because we're using JWT tokens as the primary authentication method.
    """

    def enforce_csrf(self, request):
        """
        Override to disable CSRF validation for API endpoints.
        """
        return  # Do not enforce CSRF