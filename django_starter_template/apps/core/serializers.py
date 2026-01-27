"""
Custom serializers for core authentication endpoints
"""

from rest_framework import serializers
from rest_framework_simplejwt.serializers import (
    TokenRefreshSerializer,
    TokenBlacklistSerializer,
)
from rest_framework_simplejwt.exceptions import InvalidToken
from django.contrib.admin.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone
from allauth.socialaccount.models import SocialAccount
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer, PasswordChangeSerializer
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str

User = get_user_model()


class FileUploadSerializer(serializers.Serializer):
    """Serializer for file upload requests"""

    file = serializers.FileField()


# Authentication Serializers
class CustomRegisterSerializer(RegisterSerializer):
    """Custom registration serializer for dj-rest-auth"""

    first_name = serializers.CharField(required=True, max_length=150)
    last_name = serializers.CharField(required=True, max_length=150)
    phone_number = serializers.CharField(
        required=False, max_length=15, allow_blank=True
    )
    user_id = serializers.CharField(required=False, max_length=50, allow_blank=True)
    role = serializers.CharField(required=False, max_length=50, allow_blank=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove username field since we use email as USERNAME_FIELD
        if "username" in self.fields:
            del self.fields["username"]

        # Make passwords optional - they'll be auto-generated if not provided
        self.fields["password1"].required = False
        self.fields["password1"].help_text = (
            "Optional. If not provided, a random password will be set."
        )
        self.fields["password2"].required = False
        self.fields["password2"].help_text = (
            "Optional. If not provided, a random password will be set."
        )

    def validate_password1(self, password):
        # If password is provided, validate it; otherwise, we'll generate one
        if password:
            return super().validate_password1(password)
        return password

    def validate(self, data):
        # Auto-generate password if not provided
        if not data.get("password1"):
            import random
            import string

            random_password = "".join(
                random.choices(string.ascii_letters + string.digits, k=12)
            )
            data["password1"] = random_password
            data["password2"] = random_password
        elif not data.get("password2"):
            data["password2"] = data["password1"]

        # Call parent validate method
        return super().validate(data)

    def validate_email(self, email):
        """Custom email validation to provide better error messages"""
        email = super().validate_email(email)
        site_name = settings.SITE_NAME
        if site_name:
            # Check for protected system emails
            if email == f"anonymous@{site_name}.system":
                raise serializers.ValidationError(
                    "This email address is reserved for system use and cannot be registered."
                )

        # Check if email already exists
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                "A user with this email address already exists."
            )

        return email

    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data.update(
            {
                "first_name": self.validated_data.get("first_name", ""),
                "last_name": self.validated_data.get("last_name", ""),
                "phone_number": self.validated_data.get("phone_number", ""),
                "user_id": self.validated_data.get("user_id") or None,
                "role": self.validated_data.get("role", ""),
            }
        )
        return data

    def save(self, request):
        user = super().save(request)

        # Set additional fields on user
        user.first_name = self.validated_data.get("first_name", "")
        user.last_name = self.validated_data.get("last_name", "")
        user.user_id = self.validated_data.get("user_id") or None

        # Set role if provided
        role_name = self.validated_data.get("role")
        if role_name:
            try:
                from apps.accounts.models import UserRole

                role, created = UserRole.objects.get_or_create(name=role_name)
                user.role = role
            except Exception as e:
                # Log error but don't fail registration
                import logging

                logger = logging.getLogger(__name__)
                logger.warning(
                    f"Could not set role {role_name} for user {user.email}: {str(e)}"
                )

        user.save()

        # Create or update user profile with additional fields
        from apps.accounts.models import UserProfile

        profile, created = UserProfile.objects.get_or_create(user=user)
        profile.phone_number = self.validated_data.get("phone_number", "")
        profile.save()

        return user


class CustomLoginSerializer(LoginSerializer):
    """Custom login serializer that uses email instead of username."""

    username = None
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        if email and password:
            # Check if user exists and is approved (for staff)
            try:
                user = User.objects.get(email=email)
                if user.is_staff and not user.is_approved:
                    raise serializers.ValidationError(
                        "Your account is pending approval. Please contact your administrator."
                    )
                if (
                    user.account_locked_until
                    and user.account_locked_until > timezone.now()
                ):
                    raise serializers.ValidationError(
                        "Your account is temporarily locked. Please try again later."
                    )
                if user and user.check_password(password):
                    attrs["user"] = user
                    return attrs
                else:
                    raise serializers.ValidationError(
                        "Unable to log in with provided credentials."
                    )
            except User.DoesNotExist:
                pass
        else:
            raise serializers.ValidationError('Must include "email" and "password".')

        return super().validate(attrs)


class CustomLogoutSerializer(TokenBlacklistSerializer):
    """
    Custom logout serializer that reads refresh token from cookies
    instead of request body, since frontend cannot access httpOnly cookies.
    """

    refresh = serializers.CharField(required=False, write_only=True)

    def validate(self, attrs):
        # Get refresh token from cookies if not provided in request body
        request = self.context.get("request")
        if not request:
            raise InvalidToken("No request context available.")

        refresh_token = attrs.get("refresh") or request.COOKIES.get("refresh")
        if not refresh_token:
            raise InvalidToken("No refresh token found in request body or cookies.")

        # Set the refresh token for parent validation
        attrs["refresh"] = refresh_token

        try:
            return super().validate(attrs)
        except Exception as e:
            error_msg = str(e)
            if "User matching query does not exist" in error_msg:
                raise InvalidToken("Token contains invalid user.")
            elif "Token is invalid or expired" in error_msg:
                raise InvalidToken("Token is invalid or expired.")
            elif "Signature has expired" in error_msg:
                raise InvalidToken("Token has expired.")
            else:
                # Re-raise the original exception for other errors
                raise


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """
    Custom token refresh serializer that reads refresh token from request body
    (primary method) or cookies (fallback). Supports both token-based and 
    cookie-based refresh flows.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Keep refresh field required for proper validation
        self.fields["refresh"].required = True
        self.fields["refresh"].allow_blank = False

    def extract_refresh_token(self):
        """
        Extract refresh token from request data or cookies.
        Primary method: request body (token-based)
        Fallback: cookies (httpOnly cookie from browser)
        """
        request = self.context.get("request")
        if not request:
            raise InvalidToken("No request context available.")

        # First check if refresh token is provided in request body (primary method)
        if "refresh" in request.data and request.data["refresh"]:
            return request.data["refresh"]

        # Fallback: check cookies (httpOnly cookie from browser)
        refresh_token = request.COOKIES.get("refresh_token")
        if refresh_token:
            return refresh_token

        # Also check for "refresh" cookie name (alternative)
        refresh_token = request.COOKIES.get("refresh")
        if refresh_token:
            return refresh_token

        # No refresh token found anywhere
        raise InvalidToken(
            "No valid refresh token found. Please provide refresh token in request body or cookies."
        )

    def validate(self, attrs):
        # Extract refresh token using our custom method
        refresh_token_str = self.extract_refresh_token()
        attrs["refresh"] = refresh_token_str

        try:
            return super().validate(attrs)
        except Exception as e:
            # Provide more detailed error information
            error_msg = str(e)
            if "Token is invalid or expired" in error_msg:
                # Try to decode the token to see what's wrong
                try:
                    from rest_framework_simplejwt.tokens import RefreshToken

                    token = RefreshToken(refresh_token_str)
                    # If we get here, the token is valid, so the error must be elsewhere
                    raise serializers.ValidationError(
                        "Token appears valid but validation failed"
                    )
                except Exception as token_error:
                    token_error_msg = str(token_error)
                    if "Signature has expired" in token_error_msg:
                        raise serializers.ValidationError("Refresh token has expired")
                    elif "Invalid signature" in token_error_msg:
                        raise serializers.ValidationError(
                            "Refresh token has invalid signature"
                        )
                    elif "Invalid token" in token_error_msg:
                        raise serializers.ValidationError("Refresh token is malformed")
                    else:
                        raise serializers.ValidationError(
                            f"Token validation error: {token_error_msg}"
                        )
            else:
                # Re-raise the original exception for other errors
                raise


class CustomPasswordChangeSerializer(PasswordChangeSerializer):
    """Custom password change serializer"""

    def save(self):
        user = super().save()
        # user.password_changed_at = timezone.now()
        # user.must_change_password = False
        # user.save(update_fields=['password_changed_at', 'must_change_password'])
        return user


class PasswordResetSerializer(serializers.Serializer):
    """
    Custom password reset serializer
    """

    email = serializers.EmailField()

    def save(self, request=None, **kwargs):
        """
        Send a password reset email using Django's PasswordResetForm.
        This mirrors the behavior of dj-rest-auth's PasswordResetSerializer.save().
        """
        from django.contrib.auth.forms import PasswordResetForm
        from django.conf import settings

        email = self.validated_data.get("email")
        # Use the form to validate and send the reset email
        form = PasswordResetForm(data={"email": email})
        if not form.is_valid():
            # Form invalid -> silently return (upstream view handles response)
            return None

        # Use custom email templates that work with frontend URL
        opts = {
            "use_https": kwargs.get("use_https", request.is_secure() if request else False),
            "from_email": kwargs.get("from_email"),
            "email_template_name": kwargs.get(
                "email_template_name", 
                "registration/password_reset_email.html"
            ),
            "subject_template_name": kwargs.get(
                "subject_template_name",
                "registration/password_reset_subject.txt"
            ),
            "request": request,
            "domain_override": getattr(settings, "FRONTEND_URL", "http://localhost:3000").replace("http://", "").replace("https://", ""),
        }
        form.save(**{k: v for k, v in opts.items() if v is not None})
        return True


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Enhanced password reset confirm serializer with better API documentation
    """

    uid = serializers.CharField()
    token = serializers.CharField()
    new_password1 = serializers.CharField()
    new_password2 = serializers.CharField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add help text and better field descriptions for API documentation
        self.fields["uid"].help_text = (
            "User ID encoded in base36 format from the password reset email"
        )
        self.fields["token"].help_text = (
            "Password reset token from the password reset email"
        )
        self.fields["new_password1"].help_text = "New password (minimum 8 characters)"
        self.fields["new_password2"].help_text = (
            "Confirm new password (must match new_password1)"
        )

        # Set labels for better API documentation
        self.fields["uid"].label = "User ID"
        self.fields["token"].label = "Reset Token"
        self.fields["new_password1"].label = "New Password"
        self.fields["new_password2"].label = "Confirm Password"

    # Use Django's SetPasswordForm to perform password validation and saving
    from django.contrib.auth.forms import SetPasswordForm

    set_password_form_class = SetPasswordForm
    user = None
    set_password_form = None

    def custom_validation(self, attrs):
        """Hook for additional validation in subclasses"""
        return None

    def validate(self, attrs):
        # Prepare token generator and a list of uid decoders to try.
        decoders = []
        if "allauth" in settings.INSTALLED_APPS:
            from allauth.account.forms import default_token_generator
            from allauth.account.utils import url_str_to_user_pk as allauth_uid_decoder
            decoders.append(lambda v: allauth_uid_decoder(v))
            # Also try Django's urlsafe_base64 as a fallback
            from django.utils.http import urlsafe_base64_decode as django_uid_decoder
            decoders.append(lambda v: force_str(django_uid_decoder(v)))
        else:
            from django.contrib.auth.tokens import default_token_generator
            from django.utils.http import urlsafe_base64_decode as django_uid_decoder
            decoders.append(lambda v: force_str(django_uid_decoder(v)))
            # If allauth is available at runtime, try its decoder as a fallback
            try:
                from allauth.account.utils import url_str_to_user_pk as allauth_uid_decoder

                decoders.append(lambda v: allauth_uid_decoder(v))
            except Exception:
                pass

        # Try each decoder until one yields a valid user pk
        last_error = None
        for decode in decoders:
            try:
                uid_str = decode(attrs["uid"])
                # Ensure we have a string representation
                uid = force_str(uid_str)
                self.user = User._default_manager.get(pk=uid)
                break
            except User.DoesNotExist as e:
                last_error = e
                self.user = None
                continue
            except (TypeError, ValueError, OverflowError) as e:
                last_error = e
                self.user = None
                continue

        if not self.user:
            raise ValidationError({"uid": [_("Invalid value")]})

        # Prefer Django's default token generator (used by PasswordResetForm)
        from django.contrib.auth.tokens import default_token_generator as django_default_token

        token_valid = False
        try:
            token_valid = bool(django_default_token.check_token(self.user, attrs["token"]))
        except Exception:
            token_valid = False

        # If not valid with Django generator, try allauth's generator (if available)
        if not token_valid and "allauth" in settings.INSTALLED_APPS:
            try:
                from allauth.account.forms import default_token_generator as allauth_token

                token_valid = bool(allauth_token.check_token(self.user, attrs["token"]))
            except Exception:
                token_valid = False

        if not token_valid:
            raise ValidationError({"token": [_("Invalid value")]})

        # Allow subclasses to add custom validation
        self.custom_validation(attrs)

        # Construct SetPasswordForm instance to validate the new passwords
        self.set_password_form = self.set_password_form_class(user=self.user, data=attrs)
        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return attrs

    def save(self):
        """Save the new password using SetPasswordForm.save()"""
        return self.set_password_form.save()


class PasswordResetConfirmResponseSerializer(serializers.Serializer):
    """
    Response serializer for password reset confirmation
    """

    detail = serializers.CharField(
        default="Password has been reset with the new password.",
        help_text="Success message confirming password reset",
    )


# Two-Factor Authentication Serializers
class TwoFactorSetupSerializer(serializers.Serializer):
    """Serializer for 2FA setup response"""

    device_id = serializers.IntegerField(read_only=True)
    provisioning_uri = serializers.CharField(read_only=True)
    qr_code = serializers.CharField(read_only=True)
    secret = serializers.CharField(read_only=True)


class TwoFactorVerifySerializer(serializers.Serializer):
    """Serializer for 2FA verification during setup"""

    token = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Token must contain only digits")
        return value


class TwoFactorVerifyLoginSerializer(serializers.Serializer):
    """Serializer for 2FA verification during login"""

    token = serializers.CharField(max_length=6, min_length=6, required=True)
    backup_code = serializers.CharField(max_length=8, min_length=8, required=False)

    def validate_token(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Token must contain only digits")
        return value

    def validate_backup_code(self, value):
        if value and not value.replace("-", "").isalnum():
            raise serializers.ValidationError("Backup code format is invalid")
        return value


class TwoFactorStatusSerializer(serializers.Serializer):
    """Serializer for 2FA status response"""

    enabled = serializers.BooleanField(read_only=True)
    confirmed = serializers.BooleanField(read_only=True)
    backup_codes_count = serializers.IntegerField(read_only=True)
    device_name = serializers.CharField(read_only=True)


class TwoFactorBackupCodesSerializer(serializers.Serializer):
    """Serializer for backup codes response"""

    backup_codes = serializers.ListField(
        child=serializers.CharField(max_length=8), read_only=True
    )


class LogEntrySerializer(serializers.ModelSerializer):
    content_type = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()

    class Meta:
        model = LogEntry
        fields = [
            "id",
            "action_flag",
            "change_message",
            "object_id",
            "object_repr",
            "content_type",
            "user",
            "action_time",
        ]

    @extend_schema_field(serializers.CharField())
    def get_content_type(self, obj):
        return ContentType.objects.get_for_id(obj.content_type_id).model

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_user(self, obj):
        return obj.user.get_username() if obj.user else None


class SystemSettingsSerializer(serializers.Serializer):
    """
    Serializer for system settings
    Uses Serializer (not ModelSerializer) to avoid exposing internal fields
    """

    # General Settings
    site_name = serializers.CharField(max_length=255, required=False)
    site_url = serializers.URLField(required=False)
    timezone = serializers.CharField(max_length=50, required=False)
    date_format = serializers.CharField(max_length=20, required=False)
    time_format = serializers.CharField(max_length=10, required=False)

    # Security Settings
    session_timeout = serializers.IntegerField(
        required=False, min_value=5, max_value=1440
    )
    max_login_attempts = serializers.IntegerField(
        required=False, min_value=1, max_value=10
    )
    password_min_length = serializers.IntegerField(
        required=False, min_value=6, max_value=32
    )
    require_2fa = serializers.BooleanField(required=False)
    allow_user_registration = serializers.BooleanField(required=False)

    # Email Settings
    email_from_name = serializers.CharField(max_length=255, required=False)
    email_from_address = serializers.EmailField(required=False)
    smtp_host = serializers.CharField(max_length=255, required=False)
    smtp_port = serializers.IntegerField(required=False, min_value=1, max_value=65535)
    smtp_use_tls = serializers.BooleanField(required=False)

    # Notification Settings
    enable_email_notifications = serializers.BooleanField(required=False)
    enable_push_notifications = serializers.BooleanField(required=False)
    notification_retention_days = serializers.IntegerField(
        required=False, min_value=7, max_value=365
    )

    # System Settings
    maintenance_mode = serializers.BooleanField(required=False)
    debug_mode = serializers.BooleanField(required=False)
    log_level = serializers.ChoiceField(
        choices=["DEBUG", "INFO", "WARNING", "ERROR"], required=False
    )
    cache_enabled = serializers.BooleanField(required=False)

    # Read-only metadata
    updated_at = serializers.DateTimeField(read_only=True)
    updated_by_email = serializers.SerializerMethodField()

    def get_updated_by_email(self, obj):
        """Get email of user who last updated settings"""
        if hasattr(obj, "updated_by") and obj.updated_by:
            return obj.updated_by.email
        return None
