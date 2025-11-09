"""
Tests for Notifications models
"""
import pytest
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from apps.notifications.models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)
from apps.core.tests.factories import UserFactory


@pytest.mark.model
class TestNotificationTemplateModel(TestCase):
    """Test cases for NotificationTemplate model"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.template = NotificationTemplate.objects.create(
            name='test_template',
            description='A test notification template',
            template_type='email',
            subject='Test Subject {{name}}',
            body='Hello {{name}}, this is a test notification.',
            variables={'name': 'string'},
            priority='medium'
        )

    def test_template_creation(self):
        """Test template creation"""
        assert self.template.name == 'test_template'
        assert self.template.template_type == 'email'
        assert self.template.subject == 'Test Subject {{name}}'
        assert self.template.body == 'Hello {{name}}, this is a test notification.'
        assert 'name' in self.template.variables
        assert self.template.priority == 'medium'
        assert self.template.is_active is True

    def test_template_string_representation(self):
        """Test string representation of template"""
        assert str(self.template) == 'test_template (email)'

    def test_template_unique_name_constraint(self):
        """Test unique constraint on template name"""
        with pytest.raises(IntegrityError):
            NotificationTemplate.objects.create(
                name='test_template',  # Same name
                template_type='sms',
                body='SMS message'
            )

    def test_template_priority_choices(self):
        """Test priority field choices"""
        valid_priorities = ['low', 'medium', 'high', 'urgent']
        for priority in valid_priorities:
            template = NotificationTemplate.objects.create(
                name=f'test_{priority}',
                template_type='email',
                body='Test body',
                priority=priority
            )
            assert template.priority == priority

    def test_template_type_choices(self):
        """Test template_type field choices"""
        valid_types = ['email', 'sms', 'push', 'in_app']
        for template_type in valid_types:
            template = NotificationTemplate.objects.create(
                name=f'test_{template_type}',
                template_type=template_type,
                body='Test body'
            )
            assert template.template_type == template_type


@pytest.mark.model
class TestNotificationModel(TestCase):
    """Test cases for Notification model"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='notification_test_template',
            template_type='email',
            subject='Test Notification',
            body='Test body {{recipient}}'
        )
        cls.notification = Notification.objects.create(
            recipient=cls.user,
            template=cls.template,
            subject='Personalized Subject',
            body='Test body Test Recipient',
            data={'recipient': 'Test Recipient'},
            priority='high'
        )

    def test_notification_creation(self):
        """Test notification creation"""
        assert self.notification.recipient == self.user
        assert self.notification.template == self.template
        assert self.notification.status == Notification.STATUS_PENDING
        assert self.notification.priority == 'high'
        assert self.notification.retry_count == 0
        assert self.notification.max_retries == 3
        assert self.notification.data == {'recipient': 'Test Recipient'}

    def test_notification_string_representation(self):
        """Test string representation of notification"""
        expected = f"Notification to {self.user} - {self.template.name}"
        assert str(self.notification) == expected

    def test_notification_status_choices(self):
        """Test status field choices"""
        valid_statuses = ['pending', 'sent', 'delivered', 'failed', 'cancelled']
        for status in valid_statuses:
            notification = Notification.objects.create(
                recipient=self.user,
                template=self.template,
                status=status
            )
            assert notification.status == status

    def test_notification_priority_choices(self):
        """Test priority field choices"""
        valid_priorities = ['low', 'medium', 'high', 'urgent']
        for priority in valid_priorities:
            notification = Notification.objects.create(
                recipient=self.user,
                template=self.template,
                priority=priority
            )
            assert notification.priority == priority


@pytest.mark.model
class TestNotificationDeliveryModel(TestCase):
    """Test cases for NotificationDelivery model"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='delivery_test_template',
            template_type='email',
            body='Test body'
        )
        cls.notification = Notification.objects.create(
            recipient=cls.user,
            template=cls.template
        )
        cls.delivery = NotificationDelivery.objects.create(
            notification=cls.notification,
            delivery_method='email',
            recipient_address='test@example.com'
        )

    def test_delivery_creation(self):
        """Test delivery creation"""
        assert self.delivery.notification == self.notification
        assert self.delivery.delivery_method == 'email'
        assert self.delivery.status == 'pending'
        assert self.delivery.recipient_address == 'test@example.com'
        assert self.delivery.retry_count == 0

    def test_delivery_string_representation(self):
        """Test string representation of delivery"""
        expected = f"email delivery for {self.notification}"
        assert str(self.delivery) == expected

    def test_delivery_unique_together_constraint(self):
        """Test unique together constraint for notification and delivery method"""
        with pytest.raises(IntegrityError):
            NotificationDelivery.objects.create(
                notification=self.notification,
                delivery_method='email',  # Same method
                recipient_address='test2@example.com'
            )

    def test_delivery_method_choices(self):
        """Test delivery_method field choices"""
        valid_methods = ['email', 'sms', 'push', 'in_app']
        for method in valid_methods:
            # Create a separate notification for each delivery method test
            notification = Notification.objects.create(
                recipient=UserFactory(),
                template=self.template,
                subject='Test Subject',
                body='Test Body'
            )
            delivery = NotificationDelivery.objects.create(
                notification=notification,
                delivery_method=method,
                recipient_address='test@example.com'
            )
            assert delivery.delivery_method == method

    def test_delivery_status_choices(self):
        """Test status field choices"""
        valid_statuses = ['pending', 'sent', 'delivered', 'failed', 'bounced']
        for status in valid_statuses:
            # Create a separate notification for each status test
            notification = Notification.objects.create(
                recipient=UserFactory(),
                template=self.template,
                subject='Test Subject',
                body='Test Body'
            )
            delivery = NotificationDelivery.objects.create(
                notification=notification,
                delivery_method='email',
                recipient_address='test@example.com',
                status=status
            )
            assert delivery.status == status


@pytest.mark.model
class TestNotificationPreferenceModel(TestCase):
    """Test cases for NotificationPreference model"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.prefs = NotificationPreference.objects.create(
            user=cls.user,
            email_enabled=False,
            sms_enabled=True,
            push_enabled=True,
            in_app_enabled=True,
            exam_notifications=False,
            moderation_notifications=True
        )

    def test_preference_creation(self):
        """Test preference creation"""
        assert self.prefs.user == self.user
        assert self.prefs.email_enabled is False
        assert self.prefs.sms_enabled is True
        assert self.prefs.push_enabled is True
        assert self.prefs.in_app_enabled is True
        assert self.prefs.exam_notifications is False
        assert self.prefs.moderation_notifications is True
        assert self.prefs.system_notifications is True  # Default
        assert self.prefs.deadline_notifications is True  # Default

    def test_preference_string_representation(self):
        """Test string representation of preferences"""
        expected = f"Preferences for {self.user}"
        assert str(self.prefs) == expected

    def test_preference_defaults(self):
        """Test default values for preferences"""
        user2 = UserFactory()
        prefs2 = NotificationPreference.objects.create(user=user2)
        assert prefs2.email_enabled is True
        assert prefs2.sms_enabled is False
        assert prefs2.push_enabled is True
        assert prefs2.in_app_enabled is True
        assert prefs2.exam_notifications is True
        assert prefs2.moderation_notifications is True
        assert prefs2.system_notifications is True
        assert prefs2.deadline_notifications is True


@pytest.mark.model
class TestNotificationEventModel(TestCase):
    """Test cases for NotificationEvent model"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.event = NotificationEvent.objects.create(
            event_type=NotificationEvent.EVENT_EXAM_CREATED,
            name='Exam Created Event',
            description='Triggered when an exam is created'
        )

    def test_event_creation(self):
        """Test event creation"""
        assert self.event.event_type == NotificationEvent.EVENT_EXAM_CREATED
        assert self.event.name == 'Exam Created Event'
        assert self.event.description == 'Triggered when an exam is created'
        assert self.event.is_active is True

    def test_event_string_representation(self):
        """Test string representation of event"""
        assert str(self.event) == 'Exam Created Event'

    def test_event_unique_event_type_constraint(self):
        """Test unique constraint on event_type"""
        with pytest.raises(IntegrityError):
            NotificationEvent.objects.create(
                event_type=NotificationEvent.EVENT_EXAM_CREATED,  # Same type
                name='Another Exam Created Event'
            )

    def test_event_type_choices(self):
        """Test event_type field choices"""
        valid_events = [
            NotificationEvent.EVENT_EXAM_SUBMITTED,
            NotificationEvent.EVENT_EXAM_REVIEWED,
            NotificationEvent.EVENT_EXAM_APPROVED,
            NotificationEvent.EVENT_MODERATION_ASSIGNED,
            NotificationEvent.EVENT_MODERATION_COMPLETED,
            NotificationEvent.EVENT_DEADLINE_APPROACHING,
            NotificationEvent.EVENT_DEADLINE_OVERDUE,
        ]
        for event_type in valid_events:
            event = NotificationEvent.objects.create(
                event_type=event_type,
                name=f'Test {event_type}'
            )
            assert event.event_type == event_type