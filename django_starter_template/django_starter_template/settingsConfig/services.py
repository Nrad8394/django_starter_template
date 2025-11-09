"""
External Services Configuration for the Application
====================================================

This module contains configurations for all external services including:
- Email service settings

"""
from decouple import config

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='benjaminkaranja8393@gmail.com')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='kdsijc amosa asoms')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@domain.com')
