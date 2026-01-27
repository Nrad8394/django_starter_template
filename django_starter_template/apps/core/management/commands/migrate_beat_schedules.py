"""
Management command to migrate existing Celery Beat schedules to database.
This converts schedules from CELERY_BEAT_SCHEDULE to django-celery-beat models
and also registers recommended periodic tasks for the system.
"""

from django.core.management.base import BaseCommand
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
from django.conf import settings
import json
import importlib
from celery import current_app


class Command(BaseCommand):
    help = "Migrate Celery Beat schedules from settings to database and register recommended tasks"

    def add_arguments(self, parser):
        parser.add_argument(
            "--register-recommended",
            action="store_true",
            help="Register recommended periodic tasks for the system",
        )

    def handle(self, *args, **options):
        """Migrate schedules defined in CELERY_BEAT_SCHEDULE to database"""

        beat_schedule = getattr(settings, "CELERY_BEAT_SCHEDULE", {})

        if not beat_schedule:
            self.stdout.write(
                self.style.WARNING("No schedules found in CELERY_BEAT_SCHEDULE")
            )
        else:
            self.stdout.write(f"Found {len(beat_schedule)} schedules to migrate")
            self._migrate_beat_schedule(beat_schedule)

        # Register recommended periodic tasks if requested
        if options.get("register_recommended"):
            self.stdout.write("\n" + "=" * 70)
            self.stdout.write("Registering recommended periodic tasks...")
            self.stdout.write("=" * 70)
            self._register_recommended_tasks()

    def _migrate_beat_schedule(self, beat_schedule):
        """Migrate schedules from CELERY_BEAT_SCHEDULE"""
        created_count = 0
        updated_count = 0

        for schedule_name, schedule_config in beat_schedule.items():
            task_name = schedule_config["task"]
            schedule_seconds = schedule_config.get("schedule", 0)

            # Handle schedule (assuming seconds for now)
            if isinstance(schedule_seconds, (int, float)):
                # Create or get interval schedule
                schedule_obj, _ = IntervalSchedule.objects.get_or_create(
                    every=int(schedule_seconds),
                    period=IntervalSchedule.SECONDS,
                )

                # Create or update periodic task
                periodic_task, created = PeriodicTask.objects.get_or_create(
                    name=schedule_name,
                    defaults={
                        "task": task_name,
                        "interval": schedule_obj,
                        "enabled": True,
                        "description": f"Migrated from CELERY_BEAT_SCHEDULE: {task_name}",
                    },
                )

                if not created:
                    # Update existing task
                    periodic_task.task = task_name
                    periodic_task.interval = schedule_obj
                    periodic_task.enabled = True
                    periodic_task.save()
                    updated_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"✓ Updated: {schedule_name} -> {task_name}")
                    )
                else:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f"✓ Created: {schedule_name} -> {task_name}")
                    )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"⚠ Skipped: {schedule_name} (complex schedule type not supported)"
                    )
                )

        self.stdout.write("\n" + "=" * 70)
        self.stdout.write(self.style.SUCCESS("✅ Migration complete!"))
        self.stdout.write(f"   Created: {created_count}")
        self.stdout.write(f"   Updated: {updated_count}")
        self.stdout.write("=" * 70)

    def _register_recommended_tasks(self):
        """Register recommended periodic tasks for the system"""
        
        # Define recommended periodic tasks grouped by app for clarity
        recommended_tasks = [
            # apps.core tasks
            {
                "name": "cleanup_expired_sessions",
                "task": "apps.core.tasks.clear_expired_cache",
                "schedule_type": "crontab",
                "crontab": {"hour": 3, "minute": 0},  # Daily at 3 AM
                "description": "Clean up expired user sessions daily",
                "enabled": True,
            },

            # apps.accounts tasks
            {
                "name": "deactivate_inactive_users",
                "task": "apps.accounts.tasks.deactivate_inactive_users",
                "schedule_type": "crontab",
                "crontab": {"hour": 3, "minute": 30},  # Daily at 3:30 AM
                "description": "Deactivate users who have been inactive for a long period",
                "enabled": True,
            },
            {
                "name": "cleanup_expired_rate_limits",
                "task": "apps.accounts.tasks.cleanup_expired_rate_limits",
                "schedule_type": "interval",
                "interval": {"every": 60, "period": "minutes"},
                "description": "Clean up expired rate limit records and unblock expired blocks",
                "enabled": True,
            },

            # apps.notifications tasks
            {
                "name": "process_notification_queue",
                "task": "apps.notifications.tasks.process_notification_queue",
                "schedule_type": "interval",
                "interval": {"every": 5, "period": "minutes"},
                "description": "Process and send pending notifications every 5 minutes",
                "enabled": True,
            },
            {
                "name": "send_scheduled_notifications",
                "task": "apps.notifications.tasks.send_scheduled_notifications",
                "schedule_type": "interval",
                "interval": {"every": 1, "period": "minutes"},
                "description": "Enqueue notifications whose scheduled_at has arrived (every minute)",
                "enabled": True,
            },
            {
                "name": "retry_failed_notifications",
                "task": "apps.notifications.tasks.retry_failed_notifications",
                "schedule_type": "interval",
                "interval": {"every": 15, "period": "minutes"},
                "description": "Retry failed notifications periodically",
                "enabled": True,
            },
            {
                "name": "cleanup_old_notifications",
                "task": "apps.notifications.tasks.cleanup_old_notifications",
                "schedule_type": "crontab",
                "crontab": {"hour": 4, "minute": 0},  # Daily at 4 AM
                "description": "Cleanup old notifications daily",
                "enabled": True,
            },
            {
                "name": "generate_notification_analytics",
                "task": "apps.notifications.tasks.generate_notification_analytics",
                "schedule_type": "crontab",
                "crontab": {"hour": 5, "minute": 0},  # Daily at 5 AM
                "description": "Generate notification delivery analytics daily",
                "enabled": False,
            },
            {
                "name": "send_event_notifications",
                "task": "apps.notifications.tasks.send_event_notifications",
                "schedule_type": "interval",
                "interval": {"every": 1, "period": "minutes"},
                "description": "(Disabled by default) Placeholder for event-based notifications",
                "enabled": False,
            },
        ]

        created_count = 0
        skipped_count = 0

        for task_config in recommended_tasks:
            # Check if task already exists
            if PeriodicTask.objects.filter(name=task_config["name"]).exists():
                self.stdout.write(
                    self.style.WARNING(f"  ⏭️  Skipped (already exists): {task_config['name']}")
                )
                skipped_count += 1
                continue

            # Create schedule based on type
            if task_config["schedule_type"] == "interval":
                interval_config = task_config["interval"]
                schedule, _ = IntervalSchedule.objects.get_or_create(
                    every=interval_config["every"],
                    period=interval_config["period"],
                )
                schedule_kwargs = {"interval": schedule}
            elif task_config["schedule_type"] == "crontab":
                crontab_config = task_config["crontab"]
                schedule, _ = CrontabSchedule.objects.get_or_create(
                    **crontab_config
                )
                schedule_kwargs = {"crontab": schedule}
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f"  ⚠️  Skipped (unknown schedule type): {task_config['name']}"
                    )
                )
                continue

            # Create periodic task
            try:
                # Attempt to import the module that should expose the task
                task_name = task_config["task"]
                module_path = ".".join(task_name.split(".")[:-1]) if "." in task_name else None
                if module_path:
                    try:
                        importlib.import_module(module_path)
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"  ⚠ Could not import module {module_path}: {e}"))

                # Warn if the task is not registered in the running Celery app
                if task_name not in current_app.tasks:
                    self.stdout.write(self.style.WARNING(f"  ⚠ Task {task_name} not registered in Celery app (will still create periodic task)"))

                PeriodicTask.objects.create(
                    name=task_config["name"],
                    task=task_config["task"],
                    enabled=task_config["enabled"],
                    description=task_config["description"],
                    **schedule_kwargs,
                )
                created_count += 1
                status = "✅" if task_config["enabled"] else "⚪"
                self.stdout.write(
                    self.style.SUCCESS(f"  {status} Created: {task_config['name']}")
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"  ❌ Failed to create {task_config['name']}: {e}")
                )

        self.stdout.write("\n" + "=" * 70)
        self.stdout.write(self.style.SUCCESS("✅ Recommended tasks registration complete!"))
        self.stdout.write(f"   Created: {created_count}")
        self.stdout.write(f"   Skipped: {skipped_count}")
        self.stdout.write("=" * 70)
        self.stdout.write("\n💡 Next steps:")
        self.stdout.write(
            "   1. Start Celery worker: celery -A django_starter_template worker --loglevel=info"
        )
        self.stdout.write(
            "   2. Start Celery beat: celery -A django_starter_template beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler"
        )
        self.stdout.write(
            "   3. Manage schedules in Django Admin: /admin/django_celery_beat/"
        )
        self.stdout.write("")
