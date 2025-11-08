import pytest
from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from apps.security.models import (
    AuditLog, RateLimit, SecurityEvent, SecuritySettings,
    APIKey, EncryptedField
)
from datetime import timedelta


User = get_user_model()


class AuditLogModelTest(TestCase):
    """Test cases for AuditLog model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_audit_log_creation(self):
        """Test creating an audit log entry"""
        audit_log = AuditLog.objects.create(
            user=self.user,
            event_type=AuditLog.EventType.LOGIN,
            severity=AuditLog.Severity.LOW,
            description='Test login',
            ip_address='192.168.1.1',
            user_agent='Test Agent'
        )

        self.assertEqual(audit_log.user, self.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.LOGIN)
        self.assertEqual(audit_log.severity, AuditLog.Severity.LOW)
        self.assertEqual(str(audit_log), f"login - {self.user} - {audit_log.timestamp}")

    def test_audit_log_without_user(self):
        """Test creating an audit log without a user"""
        audit_log = AuditLog.objects.create(
            event_type=AuditLog.EventType.FAILED_LOGIN,
            severity=AuditLog.Severity.MEDIUM,
            description='Failed login attempt',
            ip_address='192.168.1.1'
        )

        self.assertIsNone(audit_log.user)
        self.assertEqual(audit_log.event_type, AuditLog.EventType.FAILED_LOGIN)


class RateLimitModelTest(TestCase):
    """Test cases for RateLimit model"""

    def test_rate_limit_creation(self):
        """Test creating a rate limit entry"""
        rate_limit = RateLimit.objects.create(
            limit_type=RateLimit.LimitType.IP,
            identifier='192.168.1.1',
            endpoint='/api/test/',
            request_count=5,
            window_start=timezone.now(),
            window_end=timezone.now() + timedelta(minutes=1)
        )

        self.assertEqual(rate_limit.limit_type, RateLimit.LimitType.IP)
        self.assertEqual(rate_limit.identifier, '192.168.1.1')
        self.assertEqual(rate_limit.request_count, 5)
        self.assertFalse(rate_limit.is_blocked)

    def test_rate_limit_blocked(self):
        """Test blocked rate limit"""
        rate_limit = RateLimit.objects.create(
            limit_type=RateLimit.LimitType.IP,
            identifier='192.168.1.1',
            endpoint='/api/test/',
            request_count=100,
            window_start=timezone.now(),
            window_end=timezone.now() + timedelta(minutes=1),
            is_blocked=True,
            blocked_until=timezone.now() + timedelta(minutes=15)
        )

        self.assertTrue(rate_limit.is_blocked)
        self.assertIsNotNone(rate_limit.blocked_until)

    def test_rate_limit_expired_property(self):
        """Test the is_expired property"""
        # Not expired
        future_time = timezone.now() + timedelta(minutes=1)
        rate_limit = RateLimit(
            window_end=future_time
        )
        self.assertFalse(rate_limit.is_expired)

        # Expired
        past_time = timezone.now() - timedelta(minutes=1)
        rate_limit = RateLimit(
            window_end=past_time
        )
        self.assertTrue(rate_limit.is_expired)


class SecurityEventModelTest(TestCase):
    """Test cases for SecurityEvent model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_security_event_creation(self):
        """Test creating a security event"""
        event = SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Brute force attack detected',
            description='Multiple failed login attempts',
            severity=AuditLog.Severity.HIGH,
            ip_address='192.168.1.1',
            user=self.user
        )

        self.assertEqual(event.event_type, SecurityEvent.EventType.BRUTE_FORCE)
        self.assertEqual(event.status, SecurityEvent.Status.ACTIVE)
        self.assertEqual(event.severity, AuditLog.Severity.HIGH)

    def test_security_event_resolve(self):
        """Test resolving a security event"""
        event = SecurityEvent.objects.create(
            event_type=SecurityEvent.EventType.BRUTE_FORCE,
            title='Brute force attack detected',
            description='Multiple failed login attempts',
            severity=AuditLog.Severity.HIGH
        )

        event.resolve(self.user, 'Resolved by admin')

        self.assertEqual(event.status, SecurityEvent.Status.RESOLVED)
        self.assertEqual(event.resolved_by, self.user)
        self.assertIsNotNone(event.resolved_at)
        self.assertEqual(event.resolution_notes, 'Resolved by admin')


class SecuritySettingsModelTest(TestCase):
    """Test cases for SecuritySettings model"""

    def test_security_settings_creation(self):
        """Test creating security settings"""
        settings = SecuritySettings.objects.create(
            setting_type=SecuritySettings.SettingType.RATE_LIMIT,
            name='Test Rate Limit',
            description='Test rate limiting settings',
            config={'requests_per_minute': 100},
            is_enabled=True
        )

        self.assertEqual(settings.setting_type, SecuritySettings.SettingType.RATE_LIMIT)
        self.assertEqual(settings.name, 'Test Rate Limit')
        self.assertTrue(settings.is_enabled)
        self.assertEqual(settings.config['requests_per_minute'], 100)


class APIKeyModelTest(TestCase):
    """Test cases for APIKey model"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_api_key_creation(self):
        """Test creating an API key"""
        api_key = APIKey.objects.create(
            name='Test API Key',
            key_type=APIKey.KeyType.USER,
            user=self.user,
            permissions={'read': True, 'write': False},
            rate_limit=1000
        )

        self.assertEqual(api_key.name, 'Test API Key')
        self.assertEqual(api_key.key_type, APIKey.KeyType.USER)
        self.assertEqual(api_key.user, self.user)
        self.assertEqual(len(api_key.key), 64)  # Should be 64 characters
        self.assertTrue(api_key.is_active)
        self.assertIsNone(api_key.expires_at)

    def test_api_key_expiration(self):
        """Test API key expiration"""
        # Not expired
        future_date = timezone.now() + timedelta(days=30)
        api_key = APIKey(
            expires_at=future_date
        )
        self.assertFalse(api_key.is_expired)

        # Expired
        past_date = timezone.now() - timedelta(days=1)
        api_key = APIKey(
            expires_at=past_date
        )
        self.assertTrue(api_key.is_expired)

        # No expiration
        api_key = APIKey(
            expires_at=None
        )
        self.assertFalse(api_key.is_expired)

    def test_api_key_generate_key(self):
        """Test API key generation"""
        api_key = APIKey()
        api_key.generate_key()

        self.assertEqual(len(api_key.key), 64)
        self.assertTrue(api_key.key.isalnum())


class EncryptedFieldTest(TestCase):
    """Test cases for EncryptedField"""

    def test_encrypted_field_encryption(self):
        """Test that EncryptedField encrypts and decrypts data"""
        field = EncryptedField()

        # Test encryption
        original_value = "sensitive_data_123"
        encrypted_value = field.get_prep_value(original_value)

        # Encrypted value should be different from original
        self.assertNotEqual(encrypted_value, original_value)

        # Test decryption
        decrypted_value = field.from_db_value(encrypted_value, None, None)
        self.assertEqual(decrypted_value, original_value)

    def test_encrypted_field_none_values(self):
        """Test EncryptedField handles None values"""
        field = EncryptedField()

        # Test None encryption
        encrypted_none = field.get_prep_value(None)
        self.assertIsNone(encrypted_none)

        # Test None decryption
        decrypted_none = field.from_db_value(None, None, None)
        self.assertIsNone(decrypted_none)