from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.utils import timezone
from apps.notifications.models import (
    NotificationTemplate, Notification, NotificationDelivery,
    NotificationPreference, NotificationEvent
)
from faker import Faker
import random
from datetime import timedelta
from django.conf import settings

User = get_user_model()


class Command(BaseCommand):
    help = 'Populate the notifications app with sample data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--count',
            type=int,
            default=20,
            help='Number of notifications to create (default: 20)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing data before populating'
        )

    def handle(self, *args, **options):
        fake = Faker()
        count = options['count']

        self.stdout.write(f'Populating notifications app with {count} notifications...')

        if options['clear']:
            self.stdout.write('Clearing existing data...')
            NotificationDelivery.objects.all().delete()
            Notification.objects.all().delete()
            NotificationPreference.objects.all().delete()
            NotificationEvent.objects.all().delete()
            NotificationTemplate.objects.all().delete()

        # Create notification templates
        self.create_notification_templates()

        # Create notification events
        self.create_notification_events()

        # Create user preferences
        self.create_user_preferences()

        # Create notifications
        self.create_notifications(fake, count)

        self.stdout.write(
            self.style.SUCCESS(f'Successfully populated notifications app with {count} notifications')
        )

    def create_notification_templates(self):
        """Create notification templates"""
        site_name = settings.SITE_NAME or "Django"
        templates_data = [
            {
                'name': 'Exam Created Notification',
                'description': 'Notifies when a new exam is created',
                'template_type': 'email',
                'subject': 'New Exam Created: {{exam_title}}',
                'body': ('''
                Dear {{recipient_name}},

                A new exam has been created: {{exam_title}}

                Subject: {{exam_subject}}
                Created by: {{creator_name}}
                Deadline: {{deadline}}

                Please review the exam at your earliest convenience.

                Best regards,
                {site_name} System
                ''').replace('{site_name}', site_name),
                'variables': {
                    'exam_title': 'string',
                    'exam_subject': 'string',
                    'creator_name': 'string',
                    'deadline': 'string',
                    'recipient_name': 'string'
                },
                'priority': 'medium'
            },
            {
                'name': 'Moderation Assigned',
                'description': 'Notifies moderator when assigned to a session',
                'template_type': 'email',
                'subject': 'Moderation Assignment: {{exam_title}}',
                'body': ('''
                Hello {{recipient_name}},

                You have been assigned to moderate the following exam:

                Exam: {{exam_title}}
                Subject: {{exam_subject}}
                Deadline: {{deadline}}

                Please start the moderation process as soon as possible.

                Access the moderation session here: {{moderation_url}}

                Best regards,
                {site_name} Moderation Team
                ''').replace('{site_name}', site_name),
                'variables': {
                    'exam_title': 'string',
                    'exam_subject': 'string',
                    'deadline': 'string',
                    'recipient_name': 'string',
                    'moderation_url': 'string'
                },
                'priority': 'high'
            },
            {
                'name': 'Deadline Reminder',
                'description': 'Reminds users of approaching deadlines',
                'template_type': 'email',
                'subject': 'Deadline Reminder: {{task_name}}',
                'body': ('''
                Dear {{recipient_name}},

                This is a reminder that the following task is due soon:

                Task: {{task_name}}
                Due Date: {{due_date}}
                Time Remaining: {{time_remaining}}

                Please complete this task before the deadline.

                Best regards,
                {site_name} System
                ''').replace('{site_name}', site_name),
                'variables': {
                    'task_name': 'string',
                    'due_date': 'string',
                    'time_remaining': 'string',
                    'recipient_name': 'string'
                },
                'priority': 'urgent'
            },
            {
                'name': 'SMS Exam Approved',
                'description': 'SMS notification for exam approval',
                'template_type': 'sms',
                'body': 'Your exam "{{exam_title}}" has been approved. Check your email for details.',
                'variables': {
                    'exam_title': 'string'
                },
                'priority': 'medium'
            },
            {
                'name': 'Push Notification',
                'description': 'Push notification for general updates',
                'template_type': 'push',
                'body': '{{message}}',
                'variables': {
                    'message': 'string'
                },
                'priority': 'low'
            }
        ]

        for template_data in templates_data:
            template, created = NotificationTemplate.objects.get_or_create(
                name=template_data['name'],
                defaults={
                    'description': template_data['description'],
                    'template_type': template_data['template_type'],
                    'subject': template_data.get('subject', ''),
                    'body': template_data['body'],
                    'variables': template_data['variables'],
                    'priority': template_data['priority']
                }
            )
            if created:
                self.stdout.write(f'Created template: {template.name}')

    def create_notification_events(self):
        """Create notification events"""
        events_data = [
            {
                'event_type': NotificationEvent.EVENT_EXAM_CREATED,
                'name': 'Exam Created',
                'description': 'Triggered when a new exam is created'
            },
            {
                'event_type': NotificationEvent.EVENT_EXAM_SUBMITTED,
                'name': 'Exam Submitted',
                'description': 'Triggered when an exam is submitted for review'
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
                'description': 'Triggered when a moderation session is assigned'
            },
            {
                'event_type': NotificationEvent.EVENT_MODERATION_COMPLETED,
                'name': 'Moderation Completed',
                'description': 'Triggered when a moderation session is completed'
            },
            {
                'event_type': NotificationEvent.EVENT_DEADLINE_APPROACHING,
                'name': 'Deadline Approaching',
                'description': 'Triggered when a deadline is approaching'
            },
            {
                'event_type': NotificationEvent.EVENT_DEADLINE_OVERDUE,
                'name': 'Deadline Overdue',
                'description': 'Triggered when a deadline is overdue'
            }
        ]

        templates = list(NotificationTemplate.objects.all())

        for event_data in events_data:
            event, created = NotificationEvent.objects.get_or_create(
                event_type=event_data['event_type'],
                defaults={
                    'name': event_data['name'],
                    'description': event_data['description']
                }
            )

            # Assign random templates to events
            if templates:
                event.default_email_template = random.choice([t for t in templates if t.template_type == 'email'] + [None])
                event.default_sms_template = random.choice([t for t in templates if t.template_type == 'sms'] + [None])
                event.default_push_template = random.choice([t for t in templates if t.template_type == 'push'] + [None])
                event.save()

            if created:
                self.stdout.write(f'Created event: {event.name}')

    def create_user_preferences(self):
        """Create notification preferences for users"""
        users = User.objects.all()

        for user in users:
            preference, created = NotificationPreference.objects.get_or_create(
                user=user,
                defaults={
                    'email_enabled': random.choice([True, False]),
                    'sms_enabled': random.choice([True, False]),
                    'push_enabled': random.choice([True, False]),
                    'in_app_enabled': True,  # Always enabled by default
                    'exam_notifications': random.choice([True, False]),
                    'moderation_notifications': random.choice([True, False]),
                    'system_notifications': True,  # Always enabled
                    'deadline_notifications': True,  # Always enabled
                    'email_address': user.email,
                    'phone_number': user.phone_number or '',
                    'device_tokens': [f"token_{random.randint(1000, 9999)}" for _ in range(random.randint(0, 2))]
                }
            )
            if created:
                self.stdout.write(f'Created preferences for: {user.email}')

    def create_notifications(self, fake, count):
        """Create sample notifications"""
        users = list(User.objects.all())
        templates = list(NotificationTemplate.objects.all())

        if not users or not templates:
            self.stdout.write(self.style.WARNING('No users or templates found. Skipping notification creation.'))
            return

        for i in range(count):
            recipient = random.choice(users)
            template = random.choice(templates)

            # Generate sample data based on template
            data = {}
            if template.variables:
                for var_name, var_type in template.variables.items():
                    if var_name == 'recipient_name':
                        data[var_name] = recipient.first_name
                    elif var_name == 'exam_title':
                        data[var_name] = fake.sentence(nb_words=4)
                    elif var_name == 'exam_subject':
                        data[var_name] = random.choice(['Mathematics', 'English', 'Science', 'History'])
                    elif var_name == 'creator_name':
                        data[var_name] = fake.name()
                    elif var_name == 'deadline':
                        data[var_name] = (timezone.now() + timedelta(days=random.randint(1, 7))).strftime('%Y-%m-%d')
                    elif var_name == 'task_name':
                        data[var_name] = fake.sentence(nb_words=3)
                    elif var_name == 'due_date':
                        data[var_name] = (timezone.now() + timedelta(days=random.randint(1, 3))).strftime('%Y-%m-%d')
                    elif var_name == 'time_remaining':
                        data[var_name] = f"{random.randint(1, 24)} hours"
                    elif var_name == 'moderation_url':
                        data[var_name] = f"/moderation/session/{random.randint(1, 100)}/"
                    elif var_name == 'message':
                        data[var_name] = fake.sentence()

            status = random.choice([
                Notification.STATUS_PENDING,
                Notification.STATUS_SENT,
                Notification.STATUS_DELIVERED,
                Notification.STATUS_FAILED
            ])

            notification = Notification.objects.create(
                recipient=recipient,
                template=template,
                subject=template.subject,
                body=template.body,
                data=data,
                status=status,
                priority=template.priority,
                scheduled_at=timezone.now() - timedelta(hours=random.randint(1, 48)) if random.choice([True, False]) else None,
                sent_at=timezone.now() - timedelta(hours=random.randint(0, 24)) if status in [Notification.STATUS_SENT, Notification.STATUS_DELIVERED] else None,
                delivered_at=timezone.now() - timedelta(minutes=random.randint(0, 60)) if status == Notification.STATUS_DELIVERED else None,
                content_type=random.choice(['exam', 'moderation_session', '']),
                object_id=random.randint(1, 100) if random.choice([True, False]) else None,
                retry_count=random.randint(0, 2) if status == Notification.STATUS_FAILED else 0,
                last_error=fake.sentence() if status == Notification.STATUS_FAILED else ''
            )

            # Create delivery records
            self.create_delivery_records(notification, fake)

        self.stdout.write(f'Created {count} notifications')

    def create_delivery_records(self, notification, fake):
        """Create delivery records for a notification"""
        delivery_methods = ['email', 'sms', 'push', 'in_app']

        for method in random.sample(delivery_methods, random.randint(1, 3)):
            status = random.choice(['sent', 'delivered', 'failed'])

            delivery = NotificationDelivery.objects.create(
                notification=notification,
                delivery_method=method,
                status=status,
                provider=random.choice(['sendgrid', 'twilio', 'fcm', 'internal']),
                provider_message_id=fake.uuid4() if status != 'failed' else '',
                recipient_address=self.get_recipient_address(notification.recipient, method),
                sent_at=timezone.now() - timedelta(hours=random.randint(0, 24)) if status in ['sent', 'delivered'] else None,
                delivered_at=timezone.now() - timedelta(minutes=random.randint(0, 60)) if status == 'delivered' else None,
                error_message=fake.sentence() if status == 'failed' else '',
                retry_count=random.randint(0, 2) if status == 'failed' else 0
            )

    def get_recipient_address(self, user, method):
        """Get appropriate recipient address for delivery method"""
        if method == 'email':
            return user.email
        elif method == 'sms':
            return user.phone_number or '+1234567890'
        elif method == 'push':
            return f"device_token_{random.randint(1000, 9999)}"
        elif method == 'in_app':
            return str(user.id)
        return ''