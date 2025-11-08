from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.core'
    verbose_name = 'Core'

    def ready(self):
        # Import signals here to ensure they are connected
        import apps.core.signals

        # Import spectacular extensions to ensure they are registered
        try:
            from . import spectacular_extensions
        except ImportError:
            pass

        # Import celery beat admin customizations
        try:
            from . import celery_beat_admin
        except ImportError:
            pass

        # Register the beat schedules after migration
        post_migrate.connect(self._register_celery_beat_schedules, sender=self)

    def _register_celery_beat_schedules(self, **kwargs):
        """
        Register periodic tasks with django-celery-beat for database-backed scheduling.
        This allows dynamic management of schedules through Django Admin.
        Called after migrations to avoid database access during app initialization.
        """
        try:
            from django_celery_beat.models import PeriodicTask, IntervalSchedule
            from django.db import transaction

            # Use atomic transaction to ensure data consistency
            with transaction.atomic():
                # Create or get the interval schedules
                every_1_minute, _ = IntervalSchedule.objects.get_or_create(
                    every=1,
                    period=IntervalSchedule.MINUTES,
                )
                every_10_minutes, _ = IntervalSchedule.objects.get_or_create(
                    every=10,
                    period=IntervalSchedule.MINUTES,
                )
                every_30_minutes, _ = IntervalSchedule.objects.get_or_create(
                    every=30,
                    period=IntervalSchedule.MINUTES,
                )
                every_60_minutes, _ = IntervalSchedule.objects.get_or_create(
                    every=60,
                    period=IntervalSchedule.MINUTES,
                )
                every_2_hours, _ = IntervalSchedule.objects.get_or_create(
                    every=2,
                    period=IntervalSchedule.HOURS,
                )
                every_6_hours, _ = IntervalSchedule.objects.get_or_create(
                    every=6,
                    period=IntervalSchedule.HOURS,
                )
                every_12_hours, _ = IntervalSchedule.objects.get_or_create(
                    every=12,
                    period=IntervalSchedule.HOURS,
                )
                daily, _ = IntervalSchedule.objects.get_or_create(
                    every=1,
                    period=IntervalSchedule.DAYS,
                )
                weekly, _ = IntervalSchedule.objects.get_or_create(
                    every=7,
                    period=IntervalSchedule.DAYS,
                )
                fortnightly, _ = IntervalSchedule.objects.get_or_create(
                    every=14,
                    period=IntervalSchedule.DAYS,
                )
                monthly, _ = IntervalSchedule.objects.get_or_create(
                    every=30,
                    period=IntervalSchedule.DAYS,
                )

                # Register core maintenance tasks
                # These are template tasks - customize based on your app's needs

                # Health check task - runs every 10 minutes
                health_check_task, created = PeriodicTask.objects.get_or_create(
                    name='Health Check',
                    defaults={
                        'task': 'apps.core.tasks.health_check',
                        'interval': every_10_minutes,
                        'enabled': True,
                        'description': 'Periodic health check for system monitoring',
                    }
                )
                if not created and health_check_task.interval != every_10_minutes:
                    health_check_task.interval = every_10_minutes
                    health_check_task.save()

                # Cache cleanup task - runs daily
                cache_cleanup_task, created = PeriodicTask.objects.get_or_create(
                    name='Clear Expired Cache',
                    defaults={
                        'task': 'apps.core.tasks.clear_expired_cache',
                        'interval': daily,
                        'enabled': True,
                        'description': 'Clear expired cache entries daily',
                    }
                )
                if not created and cache_cleanup_task.interval != daily:
                    cache_cleanup_task.interval = daily
                    cache_cleanup_task.save()

        except ImportError:
            # django-celery-beat not installed, skip registration
            pass
        except Exception as e:
            # Log the error but don't break app startup
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to register Celery beat schedules: {e}")