"""
Celery configuration file for the  Application
---------------------------------------------------
This module sets up a robust Celery instance integrated with Django settings.
It supports distributed task queues with Redis, provides safe worker behavior,
and enforces reliability in task execution across environments.
"""

import os
import sys
from celery import Celery
from celery.signals import setup_logging, task_failure, worker_ready
import logging

# -------------------------------------------------------------------
# 1. Default Django Settings Setup
# -------------------------------------------------------------------
# Allow Celery to run in different environments (e.g., production, staging)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_starter_template.settings')

# Ensure the project root is in Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# -------------------------------------------------------------------
# 2. Celery App Definition
# -------------------------------------------------------------------
app = Celery('django_starter_template')

# Load configuration from Django settings with CELERY_ namespace
app.config_from_object('django.conf:settings', namespace='CELERY')

# -------------------------------------------------------------------
# 3. Auto-discover Tasks from All Django Apps
# -------------------------------------------------------------------
app.autodiscover_tasks()


# -------------------------------------------------------------------
# 4. Debug / Diagnostic Task
# -------------------------------------------------------------------
@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Simple debug task for testing worker connections"""
    print(f"[DEBUG] Task Request: {self.request!r}")


# -------------------------------------------------------------------
# 5. Lifecycle & Logging Hooks
# -------------------------------------------------------------------
@setup_logging.connect
def setup_celery_logging(**kwargs):
    """
    Integrate Celery logs with Django logging config.
    Prevents Celery from overriding Django’s logger.
    """
    from django.conf import settings
    logging.config.dictConfig(settings.LOGGING)
    logging.getLogger(__name__).info("Celery logging configured successfully.")


@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    """
    Triggered once Celery worker is fully booted and connected to the broker.
    Useful for warm-up tasks or system checks.
    """
    logger = logging.getLogger(__name__)
    logger.info("✅ Celery worker is ready and connected to Redis broker.")


@task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, **kwargs):
    """
    Log detailed info when a task fails — helpful for monitoring and debugging.
    """
    logger = logging.getLogger(__name__)
    logger.error(f"❌ Task {sender.name} [{task_id}] failed: {exception}")


# -------------------------------------------------------------------
# 6. Optional: Beat Scheduler (for Periodic Tasks)
# -------------------------------------------------------------------
# If you are running Celery Beat for scheduled jobs
# Uncomment and configure schedule dictionary here

# from celery.schedules import crontab
# app.conf.beat_schedule = {
#     'cleanup-old-reports-every-midnight': {
#         'task': 'reports.tasks.cleanup_old_reports',
#         'schedule': crontab(hour=0, minute=0),
#         'options': {'expires': 3600},
#     },
# }

# -------------------------------------------------------------------
# 7. Entry Point for CLI Commands
# -------------------------------------------------------------------
if __name__ == '__main__':
    app.start()
