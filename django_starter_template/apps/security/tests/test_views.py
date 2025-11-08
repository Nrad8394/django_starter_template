import pytest
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
from apps.security.models import (
    AuditLog, RateLimit, SecurityEvent, SecuritySettings, APIKey
)


User = get_user_model()


@pytest.mark.view
class AuditLogAPITest(APITestCase):
    """Test cases for AuditLog API"""

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='admin123'
        )
        self.regular_user = User.objects.create_user(
            email='user@example.com',
            password='user123'
        )
        self.client = APIClient()

    def test_audit_log_list_requires_authentication(self):
        """Test that audit log list requires authentication"""
        url = reverse('security:auditlog-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_audit_log_list_admin_access(self):
        """Test that admin can access audit logs"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:auditlog-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_audit_log_list_regular_user_limited(self):
        """Test that regular users can only see their own logs"""
        # Create audit logs for both users
        AuditLog.objects.create(
            user=self.admin_user,
            event_type=AuditLog.EventType.LOGIN,
            description='Admin login'
        )
        AuditLog.objects.create(
            user=self.regular_user,
            event_type=AuditLog.EventType.LOGIN,
            description='User login'
        )

        self.client.force_authenticate(user=self.regular_user)
        url = reverse('security:auditlog-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return the user's own log
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['description'], 'User login')


class SecurityEventAPITest(APITestCase):
    """Test cases for SecurityEvent API"""

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='admin123'
        )
        self.client = APIClient()

    def test_security_event_list(self):
        """Test listing security events"""
        SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Test Event',
            description='Test security event'
        )

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:securityevent-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)

    def test_security_event_resolve(self):
        """Test resolving a security event"""
        event = SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Test Event',
            description='Test security event'
        )

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:securityevent-resolve', kwargs={'pk': event.pk})
        response = self.client.post(url, {'notes': 'Resolved by test'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        event.refresh_from_db()
        self.assertEqual(event.status, SecurityEvent.Status.RESOLVED)
        self.assertEqual(event.resolution_notes, 'Resolved by test')


class SecuritySettingsAPITest(APITestCase):
    """Test cases for SecuritySettings API"""

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='admin123'
        )
        self.client = APIClient()

    def test_security_settings_list(self):
        """Test listing security settings"""
        SecuritySettings.objects.create(
            setting_type=SecuritySettings.SettingType.RATE_LIMIT,
            name='Test Setting',
            config={'test': True}
        )

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:securitysettings-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)

    def test_security_settings_create(self):
        """Test creating security settings"""
        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:securitysettings-list')
        data = {
            'setting_type': SecuritySettings.SettingType.RATE_LIMIT,
            'name': 'New Test Setting',
            'description': 'Test setting description',
            'config': {'enabled': True},
            'is_enabled': True
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Test Setting')


class APIKeyAPITest(APITestCase):
    """Test cases for APIKey API"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='other123'
        )
        self.client = APIClient()

    def test_api_key_create(self):
        """Test creating an API key"""
        self.client.force_authenticate(user=self.user)
        url = reverse('security:apikey-list')
        data = {
            'name': 'Test API Key',
            'key_type': APIKey.KeyType.USER,
            'permissions': {'read': True},
            'rate_limit': 1000
        }
        response = self.client.post(url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Test API Key')
        # Key should not be returned for security reasons
        self.assertNotIn('key', response.data)

        # Verify API key was created
        api_key = APIKey.objects.get(name='Test API Key')
        self.assertEqual(api_key.user, self.user)

    def test_api_key_list_own_keys(self):
        """Test that users can only see their own API keys"""
        # Create API keys for both users
        APIKey.objects.create(
            name='User Key',
            user=self.user,
            permissions={}
        )
        APIKey.objects.create(
            name='Other User Key',
            user=self.other_user,
            permissions={}
        )

        self.client.force_authenticate(user=self.user)
        url = reverse('security:apikey-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'User Key')

    def test_api_key_regenerate(self):
        """Test regenerating an API key"""
        api_key = APIKey.objects.create(
            name='Test Key',
            user=self.user,
            permissions={}
        )
        original_key = api_key.key

        self.client.force_authenticate(user=self.user)
        url = reverse('security:apikey-regenerate', kwargs={'pk': api_key.pk})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        api_key.refresh_from_db()
        self.assertNotEqual(api_key.key, original_key)

    def test_api_key_deactivate(self):
        """Test deactivating an API key"""
        api_key = APIKey.objects.create(
            name='Test Key',
            user=self.user,
            permissions={}
        )

        self.client.force_authenticate(user=self.user)
        url = reverse('security:apikey-deactivate', kwargs={'pk': api_key.pk})
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        api_key.refresh_from_db()
        self.assertFalse(api_key.is_active)


class SecurityDashboardAPITest(APITestCase):
    """Test cases for Security Dashboard API"""

    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='admin123'
        )
        self.client = APIClient()

    def test_security_dashboard_requires_admin(self):
        """Test that security dashboard requires admin access"""
        url = reverse('security:security-dashboard')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_security_dashboard_access(self):
        """Test accessing security dashboard as admin"""
        # Create some test data
        AuditLog.objects.create(
            event_type=AuditLog.EventType.LOGIN,
            description='Test login'
        )
        SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Test Event',
            description='Test security event',
            severity=AuditLog.Severity.CRITICAL
        )

        self.client.force_authenticate(user=self.admin_user)
        url = reverse('security:security-dashboard')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('total_audit_logs', response.data)
        self.assertIn('critical_events', response.data)
        self.assertIn('recent_security_events', response.data)


class LogSecurityEventAPITest(APITestCase):
    """Test cases for logging security events"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.client = APIClient()

    def test_log_security_event(self):
        """Test logging a security event"""
        self.client.force_authenticate(user=self.user)
        url = reverse('security:log-security-event')
        data = {
            'event_type': SecurityEvent.EventType.SUSPICIOUS_IP,
            'title': 'Suspicious Activity',
            'description': 'Suspicious IP detected',
            'severity': AuditLog.Severity.MEDIUM
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        # Verify security event was created
        event = SecurityEvent.objects.get(title='Suspicious Activity')
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.event_type, SecurityEvent.EventType.SUSPICIOUS_IP)

    def test_log_security_event_missing_fields(self):
        """Test logging security event with missing required fields"""
        self.client.force_authenticate(user=self.user)
        url = reverse('security:log-security-event')
        data = {
            'event_type': SecurityEvent.EventType.SUSPICIOUS_IP
            # Missing title and description
        }
        response = self.client.post(url, data)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)