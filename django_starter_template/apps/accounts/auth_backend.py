"""
Custom authentication backend for tracking login attempts
"""
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class TrackingModelBackend(ModelBackend):
    """
    Custom authentication backend that tracks login attempts
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        Authenticate user (login attempt tracking is handled by middleware)
        """
        return super().authenticate(request, username=username, password=password, **kwargs)