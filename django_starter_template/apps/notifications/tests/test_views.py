"""
Tests for Notifications views
"""
import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.notifications.models import (
    NotificationTemplate,
    Notification,
    NotificationDelivery,
    NotificationEvent
)
from apps.core.tests.factories import UserFactory


@pytest.mark.view
class TestNotificationTemplateViewSet:
    """Test cases for NotificationTemplateViewSet"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        self.client = APIClient()
        self.admin_user = UserFactory(is_staff=True, is_superuser=True)
        self.template_email = NotificationTemplate.objects.create(
            name='email_template',
            template_type='email',
            subject='Email Subject',
            body='Email body content'
        )
        self.template_sms = NotificationTemplate.objects.create(
            name='sms_template',
            template_type='sms',
            body='SMS content'
        )

    @pytest.mark.django_db
    def test_list_templates(self):
        """Test listing notification templates"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-list')
        response = self.client.get(url)

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 2

    @pytest.mark.django_db
    def test_list_templates_filtered_by_type(self):
        """Test filtering templates by type"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-list')

        # Filter by email
        response = self.client.get(url, {'type': 'email'})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['template_type'] == 'email'

        # Filter by sms
        response = self.client.get(url, {'type': 'sms'})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['template_type'] == 'sms'

    @pytest.mark.django_db
    def test_create_template(self):
        """Test creating a new template"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-list')
        data = {
            'name': 'new_template',
            'template_type': 'push',
            'subject': 'Push Subject',
            'body': 'Push notification content',
            'variables': {'user': 'string'}
        }

        response = self.client.post(url, data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'new_template'
        assert response.data['template_type'] == 'push'

    @pytest.mark.django_db
    def test_retrieve_template(self):
        """Test retrieving a specific template"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-detail', kwargs={'pk': self.template_email.pk})

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'email_template'

    @pytest.mark.django_db
    def test_update_template(self):
        """Test updating a template"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-detail', kwargs={'pk': self.template_email.pk})
        data = {
            'name': 'updated_template',
            'template_type': 'email',
            'subject': 'Updated Subject',
            'body': 'Updated body content'
        }

        response = self.client.put(url, data, format='json')
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'updated_template'
        assert response.data['subject'] == 'Updated Subject'

    @pytest.mark.django_db
    def test_delete_template(self):
        """Test deleting a template"""
        template = NotificationTemplate.objects.create(
            name='delete_template',
            template_type='email',
            body='Delete me'
        )
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-template-detail', kwargs={'pk': template.pk})

        response = self.client.delete(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        template.refresh_from_db()
        assert template.is_deleted


@pytest.mark.view
class TestNotificationViewSet:
    """Test cases for NotificationViewSet"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        from django.db.models.signals import post_save
        from apps.notifications.signals import handle_notification_creation
        
        self.client = APIClient()
        self.admin_user = UserFactory(is_staff=True, is_superuser=True)
        self.regular_user = UserFactory()
        self.template = NotificationTemplate.objects.create(
            name='notification_template',
            template_type='email',
            subject='Test Subject',
            body='Test body'
        )
        
        # Disconnect signal to prevent status change during setup
        post_save.disconnect(handle_notification_creation, sender=Notification)
        try:
            self.notification = Notification.objects.create(
                recipient=self.regular_user,
                template=self.template,
                status='pending'
            )
        finally:
            # Reconnect signal
            post_save.connect(handle_notification_creation, sender=Notification)

    @pytest.mark.django_db
    def test_list_notifications_admin(self):
        """Test listing notifications as admin"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-list')

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1

    @pytest.mark.django_db
    def test_list_notifications_user(self):
        """Test listing notifications as regular user (filtered to own)"""
        self.client.force_authenticate(user=self.regular_user)
        url = reverse('notification-list')

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        # Should only see their own notification
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['id'] == str(self.notification.id)

    @pytest.mark.django_db
    def test_list_notifications_filtered_by_status(self):
        """Test filtering notifications by status"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-list')

        response = self.client.get(url, {'status': 'pending'})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1

    @pytest.mark.django_db
    def test_create_notification(self):
        """Test creating a notification"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-list')
        data = {
            'recipient': self.regular_user.id,
            'template': self.template.id,
            'subject': 'New notification',
            'body': 'Notification content',
            'priority': 'high'
        }

        response = self.client.post(url, data, format='json')
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['recipient'] == self.regular_user.id
        assert response.data['priority'] == 'high'

    @pytest.mark.django_db
    def test_mark_read_action(self):
        """Test marking notification as read"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-mark-read', kwargs={'pk': self.notification.pk})

        response = self.client.post(url)
        assert response.status_code == status.HTTP_200_OK
        self.notification.refresh_from_db()
        assert self.notification.status == Notification.STATUS_DELIVERED

    @pytest.mark.django_db
    def test_retry_action_failed_notification(self):
        """Test retrying a failed notification"""
        failed_notification = Notification.objects.create(
            recipient=self.regular_user,
            template=self.template,
            status=Notification.STATUS_FAILED,
            retry_count=1
        )
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-retry', kwargs={'pk': failed_notification.pk})

        response = self.client.post(url)
        assert response.status_code == status.HTTP_200_OK
        failed_notification.refresh_from_db()
        assert failed_notification.status == Notification.STATUS_PENDING
        assert failed_notification.retry_count == 2

    @pytest.mark.django_db
    def test_retry_action_non_failed_notification(self):
        """Test retrying a non-failed notification returns error"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-retry', kwargs={'pk': self.notification.pk})

        response = self.client.post(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'error' in response.data

    @pytest.mark.django_db
    def test_bulk_action_cancel(self, mocker):
        """Test bulk cancel action"""
        # Mock the signal connection to prevent status change
        from django.db.models.signals import post_save
        from apps.notifications.signals import handle_notification_creation
        
        # Disconnect the signal
        post_save.disconnect(handle_notification_creation, sender=Notification)
        
        try:
            notification2 = Notification.objects.create(
                recipient=self.regular_user,
                template=self.template,
                status='pending'
            )

            self.client.force_authenticate(user=self.admin_user)
            url = reverse('notification-bulk-action')
            data = {
                'notification_ids': [self.notification.id, notification2.id],
                'action': 'cancel'
            }

            response = self.client.post(url, data, format='json')
            assert response.status_code == status.HTTP_200_OK
            self.notification.refresh_from_db()
            notification2.refresh_from_db()
            assert self.notification.status == Notification.STATUS_CANCELLED
            assert notification2.status == Notification.STATUS_CANCELLED
        finally:
            # Reconnect the signal
            post_save.connect(handle_notification_creation, sender=Notification)
@pytest.mark.view
class TestNotificationDeliveryViewSet:
    """Test cases for NotificationDeliveryViewSet"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        self.client = APIClient()
        self.admin_user = UserFactory(is_staff=True, is_superuser=True)
        self.user = UserFactory()
        self.template = NotificationTemplate.objects.create(
            name='delivery_template',
            template_type='email',
            body='Test body'
        )
        self.notification = Notification.objects.create(
            recipient=self.user,
            template=self.template
        )
        self.delivery = NotificationDelivery.objects.create(
            notification=self.notification,
            delivery_method='email',
            recipient_address='test@example.com'
        )

    @pytest.mark.django_db
    def test_list_deliveries(self):
        """Test listing notification deliveries"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-delivery-list')

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1

    @pytest.mark.django_db
    def test_list_deliveries_filtered_by_notification(self):
        """Test filtering deliveries by notification"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-delivery-list')

        response = self.client.get(url, {'notification_id': self.notification.id})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) == 1
        assert response.data['results'][0]['notification'] == self.notification.id

    @pytest.mark.django_db
    def test_list_deliveries_filtered_by_method(self):
        """Test filtering deliveries by method"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-delivery-list')

        response = self.client.get(url, {'method': 'email'})
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1

    @pytest.mark.django_db
    def test_retrieve_delivery(self):
        """Test retrieving a specific delivery"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-delivery-detail', kwargs={'pk': self.delivery.pk})

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['delivery_method'] == 'email'


@pytest.mark.view
class TestNotificationEventViewSet:
    """Test cases for NotificationEventViewSet"""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test data"""
        self.client = APIClient()
        self.admin_user = UserFactory(is_staff=True, is_superuser=True)
        self.event = NotificationEvent.objects.create(
            event_type=NotificationEvent.EVENT_EXAM_CREATED,
            name='Exam Created Event',
            description='Triggered when an exam is created'
        )

    @pytest.mark.django_db
    def test_list_events(self):
        """Test listing notification events"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-event-list')

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1

    @pytest.mark.django_db
    def test_retrieve_event(self):
        """Test retrieving a specific event"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('notification-event-detail', kwargs={'pk': self.event.pk})

        response = self.client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'Exam Created Event'