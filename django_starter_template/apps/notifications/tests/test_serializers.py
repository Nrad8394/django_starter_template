"""
Tests for Notifications serializers
"""
import pytest
from django.test import TestCase
from django.utils import timezone
from rest_framework import serializers

from apps.notifications.models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationPreference,
    NotificationEvent
)
from apps.notifications.serializers import (
    NotificationTemplateSerializer,
    NotificationSerializer,
    NotificationDeliverySerializer,
    NotificationPreferenceSerializer,
    NotificationEventSerializer,
    SendNotificationSerializer,
    BulkNotificationSerializer
)
from apps.core.tests.factories import UserFactory


@pytest.mark.serializer
class TestNotificationTemplateSerializer(TestCase):
    """Test cases for NotificationTemplateSerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.template = NotificationTemplate.objects.create(
            name='test_template',
            template_type='email',
            subject='Test Subject',
            body='Test body {{name}}',
            variables={'name': 'string'},
            priority='medium'
        )

    def test_serialize_template(self):
        """Test serializing a notification template"""
        serializer = NotificationTemplateSerializer(self.template)
        data = serializer.data

        assert data['name'] == 'test_template'
        assert data['template_type'] == 'email'
        assert data['subject'] == 'Test Subject'
        assert data['body'] == 'Test body {{name}}'
        assert data['variables'] == {'name': 'string'}
        assert data['priority'] == 'medium'
        assert data['is_active'] is True

    def test_deserialize_valid_template(self):
        """Test deserializing valid template data"""
        data = {
            'name': 'new_template',
            'template_type': 'sms',
            'body': 'SMS content',
            'variables': {'code': 'string'}
        }
        serializer = NotificationTemplateSerializer(data=data)
        assert serializer.is_valid()
        template = serializer.save()
        assert template.name == 'new_template'
        assert template.template_type == 'sms'

    def test_deserialize_invalid_variables(self):
        """Test deserializing with invalid variables"""
        data = {
            'name': 'invalid_template',
            'template_type': 'email',
            'body': 'Test body',
            'variables': 'invalid_json'  # Should be dict
        }
        serializer = NotificationTemplateSerializer(data=data)
        assert not serializer.is_valid()
        assert 'variables' in serializer.errors


@pytest.mark.serializer
class TestNotificationSerializer(TestCase):
    """Test cases for NotificationSerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='notification_template',
            template_type='email',
            subject='Test Subject',
            body='Test body'
        )
        cls.notification = Notification.objects.create(
            recipient=cls.user,
            template=cls.template,
            subject='Personalized Subject',
            body='Test body content',
            data={'key': 'value'},
            priority='high'
        )

    def test_serialize_notification(self):
        """Test serializing a notification"""
        serializer = NotificationSerializer(self.notification)
        data = serializer.data

        assert data['recipient'] == self.user.id
        assert data['recipient_username'] == self.user.get_username()
        assert data['recipient_email'] == self.user.email
        assert data['template'] == self.template.id
        assert data['template_name'] == self.template.name
        assert data['template_type'] == self.template.template_type
        assert data['subject'] == 'Personalized Subject'
        assert data['body'] == 'Test body content'
        assert data['data'] == {'key': 'value'}
        assert data['priority'] == 'high'

    def test_deserialize_valid_notification(self):
        """Test deserializing valid notification data"""
        data = {
            'recipient': self.user.id,
            'template': self.template.id,
            'subject': 'New notification',
            'body': 'Notification content',
            'priority': 'medium'
        }
        serializer = NotificationSerializer(data=data)
        assert serializer.is_valid()
        notification = serializer.save()
        assert notification.recipient == self.user
        assert notification.template == self.template

    def test_deserialize_invalid_scheduled_at(self):
        """Test deserializing with past scheduled time"""
        past_time = timezone.now() - timezone.timedelta(hours=1)
        data = {
            'recipient': self.user.id,
            'template': self.template.id,
            'subject': 'Test',
            'body': 'Test',
            'scheduled_at': past_time
        }
        serializer = NotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'scheduled_at' in serializer.errors


@pytest.mark.serializer
class TestNotificationDeliverySerializer(TestCase):
    """Test cases for NotificationDeliverySerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='delivery_template',
            template_type='email',
            body='Test body'
        )
        cls.notification = Notification.objects.create(
            recipient=cls.user,
            template=cls.template,
            subject='Test Subject'
        )
        cls.delivery = NotificationDelivery.objects.create(
            notification=cls.notification,
            delivery_method='email',
            recipient_address='test@example.com',
            status='sent'
        )

    def test_serialize_delivery(self):
        """Test serializing a notification delivery"""
        serializer = NotificationDeliverySerializer(self.delivery)
        data = serializer.data

        assert data['notification'] == self.notification.id
        assert data['notification_subject'] == self.notification.subject
        assert data['delivery_method'] == 'email'
        assert data['recipient_address'] == 'test@example.com'
        assert data['status'] == 'sent'

    def test_deserialize_valid_delivery(self):
        """Test deserializing valid delivery data"""
        data = {
            'notification': self.notification.id,
            'delivery_method': 'sms',
            'recipient_address': '+1234567890'
        }
        serializer = NotificationDeliverySerializer(data=data)
        assert serializer.is_valid()
        delivery = serializer.save()
        assert delivery.notification == self.notification
        assert delivery.delivery_method == 'sms'


@pytest.mark.serializer
class TestNotificationPreferenceSerializer(TestCase):
    """Test cases for NotificationPreferenceSerializer"""

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

    def test_serialize_preferences(self):
        """Test serializing notification preferences"""
        serializer = NotificationPreferenceSerializer(self.prefs)
        data = serializer.data

        assert data['user'] == self.user.id
        assert data['user_username'] == self.user.get_username()
        assert data['user_email'] == self.user.email
        assert data['email_enabled'] is False
        assert data['sms_enabled'] is True
        assert data['exam_notifications'] is False
        assert data['moderation_notifications'] is True

    def test_deserialize_valid_preferences(self):
        """Test deserializing valid preference data"""
        # Use a different user to avoid OneToOne constraint violation
        other_user = UserFactory()
        data = {
            'user': other_user.id,
            'email_enabled': True,
            'sms_enabled': False,
            'exam_notifications': True,
            'device_tokens': ['token1', 'token2']
        }
        serializer = NotificationPreferenceSerializer(data=data)
        assert serializer.is_valid()

    def test_deserialize_invalid_device_tokens(self):
        """Test deserializing with invalid device tokens"""
        data = {
            'device_tokens': 'invalid_list'  # Should be list
        }
        serializer = NotificationPreferenceSerializer(data=data)
        assert not serializer.is_valid()
        assert 'device_tokens' in serializer.errors


@pytest.mark.serializer
class TestNotificationEventSerializer(TestCase):
    """Test cases for NotificationEventSerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.template = NotificationTemplate.objects.create(
            name='event_template',
            template_type='email',
            body='Event notification'
        )
        cls.event = NotificationEvent.objects.create(
            event_type=NotificationEvent.EVENT_EXAM_CREATED,
            name='Exam Created Event',
            description='Triggered when an exam is created',
            default_email_template=cls.template
        )

    def test_serialize_event(self):
        """Test serializing a notification event"""
        serializer = NotificationEventSerializer(self.event)
        data = serializer.data

        assert data['event_type'] == NotificationEvent.EVENT_EXAM_CREATED
        assert data['name'] == 'Exam Created Event'
        assert data['description'] == 'Triggered when an exam is created'
        assert data['default_email_template'] == self.template.id
        assert data['default_email_template_name'] == self.template.name
        assert data['is_active'] is True

    def test_deserialize_valid_event(self):
        """Test deserializing valid event data"""
        data = {
            'event_type': 'exam_submitted',
            'name': 'Exam Submitted Event',
            'description': 'Triggered when an exam is submitted'
        }
        serializer = NotificationEventSerializer(data=data)
        assert serializer.is_valid()
        event = serializer.save()
        assert event.event_type == 'exam_submitted'
        assert event.name == 'Exam Submitted Event'


@pytest.mark.serializer
class TestSendNotificationSerializer(TestCase):
    """Test cases for SendNotificationSerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user1 = UserFactory()
        cls.user2 = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='send_template',
            template_type='email',
            body='Send notification content'
        )

    def test_serialize_valid_data(self):
        """Test serializing valid send notification data"""
        data = {
            'recipient_ids': [self.user1.id, self.user2.id],
            'template_id': self.template.id,
            'data': {'key': 'value'},
            'priority': 'high'
        }
        serializer = SendNotificationSerializer(data=data)
        assert serializer.is_valid()

    def test_deserialize_invalid_recipient_ids(self):
        """Test deserializing with non-existent recipient IDs"""
        data = {
            'recipient_ids': [99999],  # Non-existent user ID
            'template_id': self.template.id
        }
        serializer = SendNotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'recipient_ids' in serializer.errors

    def test_deserialize_invalid_template_id(self):
        """Test deserializing with non-existent template ID"""
        data = {
            'recipient_ids': [self.user1.id],
            'template_id': 99999  # Non-existent template ID
        }
        serializer = SendNotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'template_id' in serializer.errors

    def test_deserialize_invalid_scheduled_at(self):
        """Test deserializing with past scheduled time"""
        past_time = timezone.now() - timezone.timedelta(hours=1)
        data = {
            'recipient_ids': [self.user1.id],
            'template_id': self.template.id,
            'scheduled_at': past_time
        }
        serializer = SendNotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'scheduled_at' in serializer.errors


@pytest.mark.serializer
class TestBulkNotificationSerializer(TestCase):
    """Test cases for BulkNotificationSerializer"""

    @classmethod
    def setUpTestData(cls):
        """Set up test data"""
        cls.user = UserFactory()
        cls.template = NotificationTemplate.objects.create(
            name='bulk_template',
            template_type='email',
            body='Bulk notification content'
        )
        cls.notification1 = Notification.objects.create(
            recipient=cls.user,
            template=cls.template
        )
        cls.notification2 = Notification.objects.create(
            recipient=cls.user,
            template=cls.template
        )

    def test_serialize_valid_bulk_data(self):
        """Test serializing valid bulk notification data"""
        data = {
            'notification_ids': [self.notification1.id, self.notification2.id],
            'action': 'cancel'
        }
        serializer = BulkNotificationSerializer(data=data)
        assert serializer.is_valid()

    def test_deserialize_invalid_notification_ids(self):
        """Test deserializing with non-existent notification IDs"""
        data = {
            'notification_ids': [99999],  # Non-existent notification ID
            'action': 'cancel'
        }
        serializer = BulkNotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'notification_ids' in serializer.errors

    def test_deserialize_invalid_action(self):
        """Test deserializing with invalid action"""
        data = {
            'notification_ids': [self.notification1.id],
            'action': 'invalid_action'  # Invalid action
        }
        serializer = BulkNotificationSerializer(data=data)
        assert not serializer.is_valid()
        assert 'action' in serializer.errors