"""
Custom serializers for core authentication endpoints
"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken
from django.contrib.admin.models import LogEntry
from django.contrib.contenttypes.models import ContentType
from drf_spectacular.utils import extend_schema_field


class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    """
    Custom token refresh serializer that handles user not existing
    """
    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except Exception as e:
            if 'User matching query does not exist' in str(e):
                raise InvalidToken('Token contains invalid user.')
            raise


class PasswordResetSerializer(serializers.Serializer):
    """
    Custom password reset serializer
    """
    email = serializers.EmailField()


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
        self.fields['uid'].help_text = 'User ID encoded in base36 format from the password reset email'
        self.fields['token'].help_text = 'Password reset token from the password reset email'
        self.fields['new_password1'].help_text = 'New password (minimum 8 characters)'
        self.fields['new_password2'].help_text = 'Confirm new password (must match new_password1)'

        # Set labels for better API documentation
        self.fields['uid'].label = 'User ID'
        self.fields['token'].label = 'Reset Token'
        self.fields['new_password1'].label = 'New Password'
        self.fields['new_password2'].label = 'Confirm Password'


class PasswordResetConfirmResponseSerializer(serializers.Serializer):
    """
    Response serializer for password reset confirmation
    """
    detail = serializers.CharField(
        default="Password has been reset with the new password.",
        help_text="Success message confirming password reset"
    )


class LogEntrySerializer(serializers.ModelSerializer):
    content_type = serializers.SerializerMethodField()
    user = serializers.SerializerMethodField()

    class Meta:
        model = LogEntry
        fields = [
            'id', 'action_flag', 'change_message', 'object_id', 'object_repr',
            'content_type', 'user', 'action_time'
        ]

    @extend_schema_field(serializers.CharField())
    def get_content_type(self, obj):
        return ContentType.objects.get_for_id(obj.content_type_id).model

    @extend_schema_field(serializers.CharField(allow_null=True))
    def get_user(self, obj):
        return obj.user.get_username() if obj.user else None