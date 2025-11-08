"""
Management command to migrate existing Celery Beat schedules to database.
This converts schedules from CELERY_BEAT_SCHEDULE to django-celery-beat models.
"""
from django.core.management.base import BaseCommand
from django_celery_beat.models import PeriodicTask, IntervalSchedule
from django.conf import settings
import json


class Command(BaseCommand):
    help = 'Migrate Celery Beat schedules from settings to database'

    def handle(self, *args, **options):
        """Migrate schedules defined in CELERY_BEAT_SCHEDULE to database"""

        beat_schedule = getattr(settings, 'CELERY_BEAT_SCHEDULE', {})

        if not beat_schedule:
            self.stdout.write(self.style.WARNING('No schedules found in CELERY_BEAT_SCHEDULE'))
            return

        self.stdout.write(f'Found {len(beat_schedule)} schedules to migrate')

        created_count = 0
        updated_count = 0

        for schedule_name, schedule_config in beat_schedule.items():
            task_name = schedule_config['task']
            schedule_seconds = schedule_config.get('schedule', 0)

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
                        'task': task_name,
                        'interval': schedule_obj,
                        'enabled': True,
                        'description': f'Migrated from CELERY_BEAT_SCHEDULE: {task_name}',
                    }
                )

                if not created:
                    # Update existing task
                    periodic_task.task = task_name
                    periodic_task.interval = schedule_obj
                    periodic_task.enabled = True
                    periodic_task.save()
                    updated_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Updated: {schedule_name} -> {task_name}')
                    )
                else:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'✓ Created: {schedule_name} -> {task_name}')
                    )
            else:
                self.stdout.write(
                    self.style.WARNING(
                        f'⚠ Skipped: {schedule_name} (complex schedule type not supported)'
                    )
                )

        self.stdout.write('\n' + '='*70)
        self.stdout.write(self.style.SUCCESS('✅ Migration complete!'))
        self.stdout.write(f'   Created: {created_count}')
        self.stdout.write(f'   Updated: {updated_count}')
        self.stdout.write('='*70)
        self.stdout.write('\n💡 Next steps:')
        self.stdout.write('   1. Start Celery worker: celery -A your_project worker --loglevel=info')
        self.stdout.write('   2. Start Celery beat: celery -A your_project beat --loglevel=info --scheduler django_celery_beat.schedulers:DatabaseScheduler')
        self.stdout.write('   3. Manage schedules in Django Admin: /admin/django_celery_beat/')
        self.stdout.write('')