"""
Accounts app models for user management and authentication
"""

from datetime import timedelta
from django.db import models, IntegrityError, transaction
from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.conf import settings
from apps.core.models import TimestampedModel, AuditMixin, SoftDeleteMixin, BaseModel
from .constants import UserStatusConstants
from django_otp.plugins.otp_totp.models import TOTPDevice
import uuid
import pytz



class UserProfile(TimestampedModel, AuditMixin, SoftDeleteMixin):
    """
    Extended user profile information
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="profile",
        help_text=_("User this profile belongs to"),
    )

    # Profile information
    bio = models.TextField(blank=True, help_text=_("User biography"))
    phone_number = models.CharField(
        max_length=20, blank=True, help_text=_("Phone number")
    )
    job_title = models.CharField(
        max_length=100, blank=True, help_text=_("Job title or position")
    )

    # Status and approval
    status = models.CharField(
        max_length=20,
        choices=UserStatusConstants.STATUS_CHOICES,
        default=UserStatusConstants.PENDING,
        help_text=_("User approval status"),
    )

    # Additional metadata
    approved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="approved_users",
        help_text=_("User who approved this profile"),
    )
    approved_at = models.DateTimeField(
        null=True, blank=True, help_text=_("When this profile was approved")
    )

    # User preferences
    preferred_language = models.CharField(
        max_length=10, default="en", help_text=_("User's preferred language code")
    )
    interface_theme = models.CharField(
        max_length=20,
        choices=[
            ("light", _("Light Theme")),
            ("dark", _("Dark Theme")),
            ("auto", _("Auto Theme")),
        ],
        default="light",
        help_text=_("User interface theme preference"),
    )
    allow_notifications = models.BooleanField(
        default=True, help_text=_("Whether to allow email notifications")
    )

    # Privacy settings
    show_email = models.BooleanField(
        default=False, help_text=_("Whether to show email address publicly")
    )
    show_phone = models.BooleanField(
        default=False, help_text=_("Whether to show phone number publicly")
    )

    class Meta:
        app_label = "accounts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["status"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"Profile for {self.user.email}"

    def approve(self, approved_by):
        """Approve the user profile"""
        self.status = "approved"
        self.approved_by = approved_by
        self.approved_at = timezone.now()
        self.save()

    def reject(self):
        """Reject the user profile"""
        self.status = "rejected"
        self.save()

    def suspend(self):
        """Suspend the user profile"""
        self.status = "suspended"
        self.save()


class UserSession(TimestampedModel, AuditMixin):
    """
    Track user sessions for security monitoring
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="sessions",
        help_text=_("User this session belongs to"),
    )

    session_key = models.CharField(
        max_length=40, unique=True, help_text=_("Django session key")
    )

    ip_address = models.GenericIPAddressField(help_text=_("IP address of the session"))

    user_agent = models.TextField(blank=True, help_text=_("User agent string"))

    # Additional tracking fields
    device_type = models.CharField(
        max_length=50, blank=True, help_text=_("Type of device used")
    )
    device_os = models.CharField(
        max_length=50, blank=True, help_text=_("Operating system of device")
    )
    browser = models.CharField(
        max_length=50, blank=True, help_text=_("Browser used for session")
    )
    location_info = models.JSONField(
        null=True, blank=True, help_text=_("Geographic location information")
    )
    device_info = models.JSONField(
        null=True, blank=True, help_text=_("Parsed device information from user agent")
    )

    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text=_("When this session was revoked (if applicable)"),
    )

    expires_at = models.DateTimeField(help_text=_("When this session expires"))

    last_activity = models.DateTimeField(
        default=timezone.now, help_text=_("Last activity timestamp")
    )

    class Meta:
        app_label = "accounts"
        ordering = ["-last_activity"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["session_key"]),
            models.Index(fields=["revoked_at"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["last_activity"]),
        ]

    def __str__(self):
        return f"Session for {self.user.email} from {self.ip_address}"

    def is_expired(self):
        """Check if session has expired based on Django session"""
        from django.contrib.sessions.models import Session

        try:
            django_session = Session.objects.get(session_key=self.session_key)
            # Handle timezone-aware or naive expire_date
            if timezone.is_naive(django_session.expire_date):
                expire_date_utc = timezone.make_aware(
                    django_session.expire_date, timezone=pytz.UTC
                )
            else:
                expire_date_utc = django_session.expire_date
            # Compare with current time in UTC
            return expire_date_utc <= timezone.now()
        except Session.DoesNotExist:
            return True

    @property
    def is_active(self):
        """Check if session is active (not expired and not revoked)"""
        return not (self.revoked_at or self.is_expired())

    def update_activity(self):
        """Update last activity timestamp and sync expiration with Django session"""
        from django.contrib.sessions.models import Session

        try:
            django_session = Session.objects.get(session_key=self.session_key)
            UserSession.objects.filter(id=self.id).update(
                last_activity=timezone.now(), expires_at=django_session.expire_date
            )
        except Session.DoesNotExist:
            # If Django session doesn't exist, mark as inactive
            UserSession.objects.filter(id=self.id).update(is_active=False)

    def expire(self):
        """Mark session as expired"""
        # Since expiration is handled by is_expired(), this method is deprecated
        # But keep for compatibility
        pass

    def revoke(self, reason=None):
        """Revoke session with optional reason"""
        UserSession.objects.filter(id=self.id).update(revoked_at=timezone.now())
        # Could add reason to a field if needed in the future

    @classmethod
    def create_session(cls, user, request, created_via="login"):
        """
        Create a new session record for tracking

        Args:
            user: The user this session belongs to
            request: The HTTP request object
            created_via: How this session was created (login, middleware_recovery, etc.)
        """
        from apps.core.utils import get_client_ip
        from apps.core.services import DeviceDetectionService, GeoIPService
        from django.contrib.sessions.models import Session

        session_key = request.session.session_key
        ip_address = get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        device_info = DeviceDetectionService.parse_user_agent(user_agent)
        location_info = GeoIPService.get_location_info(ip_address)

        # Set expiration to 1 hour from now for session management
        session_expires_at = timezone.now() + timedelta(seconds=3600)

        # Ensure Django session also expires in 1 hour
        request.session.set_expiry(3600)

        # Check if session already exists (active or inactive)
        existing_session = cls.objects.filter(session_key=session_key).first()
        if existing_session:
            # Update existing session instead of creating new one
            existing_session.user = user
            existing_session.ip_address = ip_address
            existing_session.user_agent = user_agent
            existing_session.device_info = device_info
            existing_session.location_info = location_info
            existing_session.expires_at = session_expires_at
            existing_session.save()
            session = existing_session
        else:
            # Create new session
            session = cls.objects.create(
                user=user,
                session_key=session_key,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
                location_info=location_info,
                expires_at=session_expires_at,
            )

        return session

    def calculate_risk_score(self):
        """
        Calculate a risk score for this session based on various factors

        Returns an integer score from 0-100 where higher scores indicate higher risk
        """
        score = 0

        # Factor 1: New device (30 points)
        if self.device_info:
            user_sessions = UserSession.objects.filter(
                user=self.user, device_info__isnull=False
            ).exclude(id=self.id)

            device_known = any(
                session.device_info.get("device_brand")
                == self.device_info.get("device_brand")
                and session.device_info.get("device_model")
                == self.device_info.get("device_model")
                for session in user_sessions
                if session.device_info
            )

            if not device_known:
                score += 30

        # Factor 2: New location (25 points)
        if self.location_info:
            user_sessions = UserSession.objects.filter(
                user=self.user, location_info__isnull=False
            ).exclude(id=self.id)

            location_known = any(
                session.location_info.get("country_code")
                == self.location_info.get("country_code")
                and session.location_info.get("city") == self.location_info.get("city")
                for session in user_sessions
                if session.location_info
            )

            if not location_known:
                score += 25

        # Factor 3: Unusual login time (15 points)
        # Consider login between 2 AM and 6 AM as higher risk
        login_hour = self.created_at.hour
        if 2 <= login_hour <= 6:
            score += 15

        # Factor 4: Bot-like user agent (20 points)
        if self.device_info and self.device_info.get("is_bot"):
            score += 20

        # Factor 5: Multiple failed login attempts recently (10 points)
        from .models import LoginAttempt

        recent_failures = LoginAttempt.objects.filter(
            email=self.user.email,
            success=False,
            created_at__gte=timezone.now() - timedelta(hours=24),
        ).count()

        if recent_failures > 3:
            score += 10

        # Ensure score doesn't exceed 100
        return min(score, 100)

    @classmethod
    def detect_suspicious_sessions(cls, user, request):
        """
        Detect potentially suspicious sessions for a user

        Returns a list of suspicious sessions based on:
        - Multiple active sessions from different IP addresses
        - Sessions from unusual locations (basic check)
        """
        if not user or not user.is_authenticated:
            return []

        # Get current IP address
        from apps.core.utils import get_client_ip

        current_ip = get_client_ip(request)

        # Get all active sessions for this user
        active_sessions = cls.objects.filter(
            user=user, is_active=True, expires_at__gt=timezone.now()
        ).exclude(ip_address=current_ip)

        suspicious_sessions = []

        # Check for multiple sessions from different IPs
        if active_sessions.count() > 2:  # More than 2 sessions from different IPs
            suspicious_sessions.extend(active_sessions)

        # Check for sessions from very different locations (basic check)
        # This is a simplified version - in production you'd use geo-IP databases
        current_ip_parts = current_ip.split(".") if current_ip else []
        for session in active_sessions:
            if session.ip_address:
                session_ip_parts = session.ip_address.split(".")
                # Simple check: if first two octets differ significantly
                if (
                    len(current_ip_parts) >= 2
                    and len(session_ip_parts) >= 2
                    and current_ip_parts[0] != session_ip_parts[0]
                ):
                    suspicious_sessions.append(session)

        # Remove duplicates
        return list(set(suspicious_sessions))

    @property
    def risk_score(self):
        """
        Calculate a risk score for this session based on various factors.
        Returns a float between 0.0 (low risk) and 1.0 (high risk).
        """
        score = 0.0

        # Check if session is expired
        if self.is_expired:
            score += 0.3

        # Check if session is inactive
        if not self.is_active:
            score += 0.2

        # Check for suspicious location (simplified)
        # In production, you'd compare with user's known locations
        if self.location_info:
            score += 0.1  # Slightly suspicious if we have location data

        # Check device/browser consistency
        # This is a basic check - in production you'd have more sophisticated logic
        if not self.device_type or not self.browser:
            score += 0.1

        # Cap at 1.0
        return min(score, 1.0)


class LoginAttempt(TimestampedModel):
    """
    Track login attempts for security monitoring
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(help_text=_("Email address used for login attempt"))

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="login_attempts",
        help_text=_("User associated with this attempt (if successful)"),
    )

    ip_address = models.GenericIPAddressField(
        help_text=_("IP address of the login attempt")
    )

    user_agent = models.TextField(blank=True, help_text=_("User agent string"))

    # Additional tracking fields
    session_id = models.CharField(
        max_length=255, blank=True, help_text=_("Session ID for tracking")
    )
    failure_reason = models.CharField(
        max_length=100, blank=True, help_text=_("Reason for login failure")
    )
    location_info = models.JSONField(
        null=True, blank=True, help_text=_("Geographic location information")
    )
    device_type = models.CharField(
        max_length=50, blank=True, help_text=_("Type of device used")
    )
    device_os = models.CharField(
        max_length=50, blank=True, help_text=_("Operating system of device")
    )
    browser = models.CharField(
        max_length=50, blank=True, help_text=_("Browser used for login")
    )

    success = models.BooleanField(
        default=False, help_text=_("Whether the login attempt was successful")
    )

    class Meta:
        app_label = "accounts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["email"]),
            models.Index(fields=["user"]),
            models.Index(fields=["success"]),
            models.Index(fields=["created_at"]),
            models.Index(fields=["ip_address"]),
        ]

    def __str__(self):
        status = "successful" if self.success else "failed"
        return f"{status.capitalize()} login attempt for {self.email} from {self.ip_address}"


class UserRoleHistory(TimestampedModel, AuditMixin):
    """
    Audit trail for user role changes
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="role_history",
        help_text=_("User whose role was changed"),
    )

    old_role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="role_changes_from",
        help_text=_("Previous role"),
    )

    new_role = models.ForeignKey(
        UserRole,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="role_changes_to",
        help_text=_("New role"),
    )

    changed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="role_changes_made",
        help_text=_("User who made the role change"),
    )

    reason = models.TextField(blank=True, help_text=_("Reason for the role change"))

    class Meta:
        app_label = "accounts"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["changed_by"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        old_role_name = self.old_role.display_name if self.old_role else "None"
        new_role_name = self.new_role.display_name if self.new_role else "None"
        return f"Role change for {self.user.email}: {old_role_name} → {new_role_name}"
