from django.db import models
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.utils import timezone
import uuid
import json
from cryptography.fernet import Fernet
from django.core.files.base import ContentFile
import base64


class AuditLog(models.Model):
    """Model for logging security and system events"""

    class EventType(models.TextChoices):
        LOGIN = 'login', _('Login')
        LOGOUT = 'logout', _('Logout')
        PASSWORD_CHANGE = 'password_change', _('Password Change')
        PASSWORD_RESET = 'password_reset', _('Password Reset')
        PROFILE_UPDATE = 'profile_update', _('Profile Update')
        PERMISSION_CHANGE = 'permission_change', _('Permission Change')
        DATA_ACCESS = 'data_access', _('Data Access')
        DATA_MODIFICATION = 'data_modification', _('Data Modification')
        SECURITY_VIOLATION = 'security_violation', _('Security Violation')
        UNAUTHORIZED_ACCESS = 'unauthorized_access', _('Unauthorized Access')
        API_ACCESS = 'api_access', _('API Access')
        FAILED_LOGIN = 'failed_login', _('Failed Login')
        SUSPICIOUS_ACTIVITY = 'suspicious_activity', _('Suspicious Activity')

    class Severity(models.TextChoices):
        LOW = 'low', _('Low')
        MEDIUM = 'medium', _('Medium')
        HIGH = 'high', _('High')
        CRITICAL = 'critical', _('Critical')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    event_type = models.CharField(
        max_length=50,
        choices=EventType.choices,
        db_index=True
    )
    severity = models.CharField(
        max_length=20,
        choices=Severity.choices,
        default=Severity.MEDIUM,
        db_index=True
    )
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    session_key = models.CharField(max_length=40, null=True, blank=True)
    request_path = models.CharField(max_length=500, null=True, blank=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_data = models.JSONField(null=True, blank=True)
    response_status = models.IntegerField(null=True, blank=True)
    additional_data = models.JSONField(null=True, blank=True)
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'event_type']),
            models.Index(fields=['event_type', 'timestamp']),
            models.Index(fields=['severity', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.event_type} - {self.user} - {self.timestamp}"


class RateLimit(models.Model):
    """Model for rate limiting"""

    class LimitType(models.TextChoices):
        IP = 'ip', _('IP Address')
        USER = 'user', _('User')
        API_KEY = 'api_key', _('API Key')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    limit_type = models.CharField(
        max_length=20,
        choices=LimitType.choices,
        db_index=True
    )
    identifier = models.CharField(max_length=255, db_index=True)  # IP, user_id, or api_key
    endpoint = models.CharField(max_length=500, db_index=True)
    request_count = models.IntegerField(default=0)
    window_start = models.DateTimeField(default=timezone.now, db_index=True)
    window_end = models.DateTimeField(db_index=True)
    blocked_until = models.DateTimeField(null=True, blank=True)
    is_blocked = models.BooleanField(default=False)

    class Meta:
        unique_together = ['limit_type', 'identifier', 'endpoint', 'window_start']
        indexes = [
            models.Index(fields=['limit_type', 'identifier']),
            models.Index(fields=['endpoint', 'window_start']),
            models.Index(fields=['is_blocked', 'blocked_until']),
        ]

    def __str__(self):
        return f"{self.limit_type}:{self.identifier} - {self.endpoint}"

    @property
    def is_expired(self):
        return timezone.now() > self.window_end


class SecurityEvent(models.Model):
    """Model for security events and alerts"""

    class EventType(models.TextChoices):
        BRUTE_FORCE = 'brute_force', _('Brute Force Attack')
        SQL_INJECTION = 'sql_injection', _('SQL Injection Attempt')
        XSS = 'xss', _('Cross-Site Scripting')
        CSRF = 'csrf', _('CSRF Attack')
        UNAUTHORIZED_ACCESS = 'unauthorized_access', _('Unauthorized Access')
        SUSPICIOUS_IP = 'suspicious_ip', _('Suspicious IP Activity')
        MALWARE_UPLOAD = 'malware_upload', _('Malware Upload Attempt')
        DATA_BREACH = 'data_breach', _('Data Breach Attempt')
        API_ABUSE = 'api_abuse', _('API Abuse')

    class Status(models.TextChoices):
        ACTIVE = 'active', _('Active')
        RESOLVED = 'resolved', _('Resolved')
        FALSE_POSITIVE = 'false_positive', _('False Positive')
        IGNORED = 'ignored', _('Ignored')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event_type = models.CharField(
        max_length=50,
        choices=EventType.choices,
        db_index=True
    )
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=AuditLog.Severity.choices,
        default=AuditLog.Severity.MEDIUM
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='security_events'
    )
    related_audit_logs = models.ManyToManyField(
        AuditLog,
        related_name='security_events',
        blank=True
    )
    detection_data = models.JSONField(null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_security_events'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event_type', 'status']),
            models.Index(fields=['severity', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
        ]

    def __str__(self):
        return f"{self.event_type} - {self.title}"

    def resolve(self, user, notes=None):
        """Mark the security event as resolved"""
        self.status = self.Status.RESOLVED
        self.resolution_notes = notes
        self.resolved_by = user
        self.resolved_at = timezone.now()
        self.save()


class EncryptedField(models.TextField):
    """Custom field for encrypting sensitive data"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._encryption_key = None

    def get_encryption_key(self):
        """Get or generate encryption key"""
        if self._encryption_key is not None:
            return self._encryption_key
            
        from django.conf import settings
        key = getattr(settings, 'ENCRYPTION_KEY', None)
        if not key:
            # Generate a new key if not set
            key = Fernet.generate_key()
            # In production, this should be stored securely
        elif isinstance(key, str):
            # If key is a string, decode it
            key = key.encode()
        
        self._encryption_key = key
        return key

    def encrypt(self, value):
        if value is None:
            return None
        f = Fernet(self.get_encryption_key())
        return f.encrypt(value.encode()).decode()

    def decrypt(self, value):
        if value is None:
            return None
        f = Fernet(self.get_encryption_key())
        return f.decrypt(value.encode()).decode()

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        return self.decrypt(value)

    def to_python(self, value):
        if value is None:
            return value
        return self.decrypt(value)

    def get_prep_value(self, value):
        if value is None:
            return value
        return self.encrypt(value)


class SecuritySettings(models.Model):
    """Global security settings"""

    class SettingType(models.TextChoices):
        RATE_LIMIT = 'rate_limit', _('Rate Limiting')
        PASSWORD_POLICY = 'password_policy', _('Password Policy')
        SESSION_POLICY = 'session_policy', _('Session Policy')
        ENCRYPTION = 'encryption', _('Encryption')
        AUDIT = 'audit', _('Audit Logging')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    setting_type = models.CharField(
        max_length=50,
        choices=SettingType.choices,
        db_index=True
    )
    name = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    config = models.JSONField(default=dict)
    is_enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['setting_type']

    def __str__(self):
        return f"{self.setting_type} - {self.name}"


class APIKey(models.Model):
    """Model for API key management"""

    class KeyType(models.TextChoices):
        SERVICE = 'service', _('Service Account')
        USER = 'user', _('User API Key')
        INTEGRATION = 'integration', _('Third-party Integration')

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    key_type = models.CharField(
        max_length=20,
        choices=KeyType.choices,
        default=KeyType.USER
    )
    key = models.CharField(max_length=128, unique=True, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='api_keys'
    )
    permissions = models.JSONField(default=dict)  # Custom permissions for the key
    rate_limit = models.IntegerField(default=1000)  # Requests per hour
    is_active = models.BooleanField(default=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['key', 'is_active']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_type})"

    @property
    def is_expired(self):
        return self.expires_at and timezone.now() > self.expires_at

    def generate_key(self):
        """Generate a secure API key"""
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        self.key = ''.join(secrets.choice(alphabet) for _ in range(64))

    def save(self, *args, **kwargs):
        if not self.key:
            self.generate_key()
        super().save(*args, **kwargs)
