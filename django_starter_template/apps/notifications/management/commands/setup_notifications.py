from django.core.management.base import BaseCommand
from django.utils.translation import gettext_lazy as _
from apps.notifications.models import (
    NotificationTemplate,
    NotificationEvent
)


class Command(BaseCommand):
    help = 'Set up initial notification templates and events'

    def handle(self, *args, **options):
        self.stdout.write('Setting up notification templates and events...')

        # Create notification templates
        templates_data = [
            {
                'name': 'Exam Created',
                'template_type': NotificationTemplate.TYPE_IN_APP,
                'subject': '',
                'body': 'A new exam "{{ exam_title }}" has been created and assigned to you.',
                'variables': {'exam_title': 'string', 'due_date': 'string'},
                'priority': 'medium'
            },
            {
                'name': 'Exam Submitted',
                'template_type': NotificationTemplate.TYPE_IN_APP,
                'subject': '',
                'body': 'Exam "{{ exam_title }}" has been submitted successfully.',
                'variables': {'exam_title': 'string', 'submitted_at': 'string'},
                'priority': 'low'
            },
            {
                'name': 'Exam Reviewed',
                'template_type': NotificationTemplate.TYPE_IN_APP,
                'subject': '',
                'body': 'Your exam "{{ exam_title }}" has been reviewed. Status: {{ status }}.',
                'variables': {'exam_title': 'string', 'status': 'string', 'reviewer': 'string'},
                'priority': 'medium'
            },
            {
                'name': 'Moderation Assigned',
                'template_type': NotificationTemplate.TYPE_IN_APP,
                'subject': '',
                'body': 'You have been assigned to moderate exam "{{ exam_title }}".',
                'variables': {'exam_title': 'string', 'due_date': 'string'},
                'priority': 'high'
            },
            {
                'name': 'Deadline Approaching',
                'template_type': NotificationTemplate.TYPE_IN_APP,
                'subject': '',
                'body': 'Deadline approaching for exam "{{ exam_title }}". Due in {{ hours_remaining }} hours.',
                'variables': {'exam_title': 'string', 'hours_remaining': 'number'},
                'priority': 'high'
            },
            {
                'name': 'Deadline Overdue',
                'template_type': NotificationTemplate.TYPE_EMAIL,
                'subject': 'Exam Deadline Overdue',
                'body': 'The deadline for exam "{{ exam_title }}" has passed. Please submit as soon as possible.',
                'variables': {'exam_title': 'string', 'overdue_by': 'string'},
                'priority': 'urgent'
            },
            {
                'name': 'System Maintenance',
                'template_type': NotificationTemplate.TYPE_EMAIL,
                'subject': 'System Maintenance Notification',
                'body': 'Scheduled maintenance will occur on {{ maintenance_date }}. System will be unavailable for {{ duration }}.',
                'variables': {'maintenance_date': 'string', 'duration': 'string'},
                'priority': 'medium'
            }
        ]

        for template_data in templates_data:
            template, created = NotificationTemplate.objects.get_or_create(
                name=template_data['name'],
                defaults=template_data
            )
            if created:
                self.stdout.write(f'Created template: {template.name}')
            else:
                self.stdout.write(f'Template already exists: {template.name}')

        # Create notification events
        events_data = [
            {
                'event_type': NotificationEvent.EVENT_EXAM_CREATED,
                'name': 'Exam Created',
                'description': 'Triggered when a new exam is created and assigned'
            },
            {
                'event_type': NotificationEvent.EVENT_EXAM_SUBMITTED,
                'name': 'Exam Submitted',
                'description': 'Triggered when an exam is submitted by a user'
            },
            {
                'event_type': NotificationEvent.EVENT_EXAM_REVIEWED,
                'name': 'Exam Reviewed',
                'description': 'Triggered when an exam review is completed'
            },
            {
                'event_type': NotificationEvent.EVENT_EXAM_APPROVED,
                'name': 'Exam Approved',
                'description': 'Triggered when an exam is approved'
            },
            {
                'event_type': NotificationEvent.EVENT_MODERATION_ASSIGNED,
                'name': 'Moderation Assigned',
                'description': 'Triggered when moderation is assigned to a user'
            },
            {
                'event_type': NotificationEvent.EVENT_MODERATION_COMPLETED,
                'name': 'Moderation Completed',
                'description': 'Triggered when moderation is completed'
            },
            {
                'event_type': NotificationEvent.EVENT_DEADLINE_APPROACHING,
                'name': 'Deadline Approaching',
                'description': 'Triggered when exam deadline is approaching'
            },
            {
                'event_type': NotificationEvent.EVENT_DEADLINE_OVERDUE,
                'name': 'Deadline Overdue',
                'description': 'Triggered when exam deadline has passed'
            }
        ]

        for event_data in events_data:
            event, created = NotificationEvent.objects.get_or_create(
                event_type=event_data['event_type'],
                defaults=event_data
            )
            if created:
                self.stdout.write(f'Created event: {event.name}')
            else:
                self.stdout.write(f'Event already exists: {event.name}')

        # Link templates to events (simplified - in production you'd want more sophisticated logic)
        exam_created_template = NotificationTemplate.objects.get(name='Exam Created')
        exam_submitted_template = NotificationTemplate.objects.get(name='Exam Submitted')
        moderation_assigned_template = NotificationTemplate.objects.get(name='Moderation Assigned')
        deadline_approaching_template = NotificationTemplate.objects.get(name='Deadline Approaching')
        deadline_overdue_template = NotificationTemplate.objects.get(name='Deadline Overdue')

        # Update events with default templates
        NotificationEvent.objects.filter(event_type=NotificationEvent.EVENT_EXAM_CREATED).update(
            default_in_app_template=exam_created_template
        )
        NotificationEvent.objects.filter(event_type=NotificationEvent.EVENT_EXAM_SUBMITTED).update(
            default_in_app_template=exam_submitted_template
        )
        NotificationEvent.objects.filter(event_type=NotificationEvent.EVENT_MODERATION_ASSIGNED).update(
            default_in_app_template=moderation_assigned_template
        )
        NotificationEvent.objects.filter(event_type=NotificationEvent.EVENT_DEADLINE_APPROACHING).update(
            default_in_app_template=deadline_approaching_template
        )
        NotificationEvent.objects.filter(event_type=NotificationEvent.EVENT_DEADLINE_OVERDUE).update(
            default_email_template=deadline_overdue_template,
            default_in_app_template=deadline_overdue_template
        )

        self.stdout.write(
            self.style.SUCCESS('Successfully set up notification templates and events')
        )