"""
Package init: expose the Celery app the way `celery -A django_starter_template` expects.

The worker/beat containers run `celery -A django_starter_template ...`; Celery resolves
that by importing this package and looking for a Celery instance among its
attributes. With an empty __init__ (and the app living in celery_app.py
rather than the conventional celery.py) that lookup found nothing and both
containers crash-looped with "Module 'django_starter_template' has no attribute 'celery'".
"""

from .celery_app import app as celery_app

__all__ = ("celery_app",)
