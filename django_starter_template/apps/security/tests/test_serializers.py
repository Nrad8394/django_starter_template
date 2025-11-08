import pytest
from django.test import TestCase
from django.contrib.auth import get_user_model
from apps.security.models import (
    AuditLog, RateLimit, SecurityEvent, SecuritySettings, APIKey
)
from apps.security.serializers import (
    AuditLogSerializer, RateLimitSerializer, SecurityEventSerializer,
    SecuritySettingsSerializer, APIKeySerializer, APIKeyCreateSerializer
)


User = get_user_model()


class AuditLogSerializerTest(TestCase):
    """Test cases for AuditLogSerializer"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_audit_log_serializer(self):
        """Test serializing an audit log"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            severity=AuditLog.Severity.LOW,
            description='Test login',
            ip_address='192.168.1.1'
        )

        serializer = AuditLogSerializer(audit_log)
        data = serializer.data

        self.assertEqual(data['event_type'], AuditLog.EventType.LOGIN)
        self.assertEqual(data['severity'], AuditLog.Severity.LOW)
        self.assertEqual(data['description'], 'Test login')
        self.assertEqual(data['ip_address'], '192.168.1.1')
        self.assertEqual(data['user_username'], 'test@example.com')
        self.assertEqual(data['user_email'], 'test@example.com')


class SecurityEventSerializerTest(TestCase):
    """Test cases for SecurityEventSerializer"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_security_event_serializer(self):
        """Test serializing a security event"""
        event = SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Test Event',
            description='Test security event',
            severity=AuditLog.Severity.HIGH,
            user=self.user
        )

        serializer = SecurityEventSerializer(event)
        data = serializer.data

        self.assertEqual(data['event_type'], SecurityEvent.EventType.BRUTE_FORCE)
        self.assertEqual(data['title'], 'Test Event')
        self.assertEqual(data['severity'], AuditLog.Severity.HIGH)
        self.assertEqual(data['user_username'], 'test@example.com')

    def test_security_event_resolve_via_serializer(self):
        """Test resolving security event through serializer"""
        from rest_framework.test import APIRequestFactory
        from django.utils import timezone

        factory = APIRequestFactory()
        request = factory.post('/api/security/events/1/resolve/')
        request.user = self.user

        event = SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Test Event',
            description='Test security event'
        )

        serializer = SecurityEventSerializer(
            event,
            data={'status': SecurityEvent.Status.RESOLVED},
            context={'request': request},
            partial=True
        )
        self.assertTrue(serializer.is_valid())
        saved_event = serializer.save()

        self.assertEqual(saved_event.status, SecurityEvent.Status.RESOLVED)
        self.assertEqual(saved_event.resolved_by, self.user)
        self.assertIsNotNone(saved_event.resolved_at)


class APIKeySerializerTest(TestCase):
    """Test cases for APIKeySerializer"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_api_key_serializer(self):
        """Test serializing an API key"""
        api_key = APIKey.objects.create(
            name='Test API Key',
            user=self.user,
            permissions={'read': True}
        )

        serializer = APIKeySerializer(api_key)
        data = serializer.data

        self.assertEqual(data['name'], 'Test API Key')
        self.assertEqual(data['user_username'], 'test@example.com')
        self.assertEqual(data['permissions'], {'read': True})
        self.assertTrue(data['is_active'])
        self.assertIn('key', data)  # Key should be included

    def test_api_key_create_serializer(self):
        """Test API key creation serializer"""
        from rest_framework.test import APIRequestFactory

        factory = APIRequestFactory()
        request = factory.post('/api/security/api-keys/')
        request.user = self.user

        serializer = APIKeyCreateSerializer(
            data={
                'name': 'New API Key',
                'key_type': APIKey.KeyType.USER,
                'permissions': {'write': True},
                'rate_limit': 500
            },
            context={'request': request}
        )

        self.assertTrue(serializer.is_valid())
        api_key = serializer.save()

        self.assertEqual(api_key.name, 'New API Key')
        self.assertEqual(api_key.user, self.user)
        self.assertEqual(api_key.permissions, {'write': True})
        self.assertEqual(api_key.rate_limit, 500)


class SecuritySettingsSerializerTest(TestCase):
    """Test cases for SecuritySettingsSerializer"""

    def test_security_settings_serializer(self):
        """Test serializing security settings"""
        settings = SecuritySettings.objects.create(
            setting_type=SecuritySettings.SettingType.RATE_LIMIT,
            name='Test Settings',
            description='Test security settings',
            config={'enabled': True, 'limit': 100},
            is_enabled=True
        )

        serializer = SecuritySettingsSerializer(settings)
        data = serializer.data

        self.assertEqual(data['setting_type'], SecuritySettings.SettingType.RATE_LIMIT)
        self.assertEqual(data['name'], 'Test Settings')
        self.assertEqual(data['config'], {'enabled': True, 'limit': 100})
        self.assertTrue(data['is_enabled'])


class RateLimitSerializerTest(TestCase):
    """Test cases for RateLimitSerializer"""

    def test_rate_limit_serializer(self):
        """Test serializing a rate limit"""
        from django.utils import timezone
        from datetime import timedelta

        rate_limit = RateLimit.objects.create(
            limit_type=RateLimit.LimitType.IP,
            identifier='192.168.1.1',
            endpoint='/api/test/',
            request_count=5,
            window_start=timezone.now(),
            window_end=timezone.now() + timedelta(minutes=1),
            is_blocked=False
        )

        serializer = RateLimitSerializer(rate_limit)
        data = serializer.data

        self.assertEqual(data['limit_type'], RateLimit.LimitType.IP)
        self.assertEqual(data['identifier'], '192.168.1.1')
        self.assertEqual(data['endpoint'], '/api/test/')
        self.assertEqual(data['request_count'], 5)
        self.assertFalse(data['is_blocked'])