"""
Serializers for accounts app with separate serializers for different operations
"""

from typing import Optional, Dict, Any
from rest_framework import serializers
from django.contrib.auth.models import Permission
from django.contrib.auth.password_validation import validate_password
from dj_rest_auth.serializers import (
    LoginSerializer,
    PasswordChangeSerializer,
    JWTSerializer,
)
from drf_spectacular.utils import extend_schema_field
from .models import (
    User,
    UserProfile,
    UserRole,
    UserRoleHistory,
    UserSession,
    LoginAttempt,
)
from .services import UserService, RoleService
from .constants import UserRoleConstants


class FlexibleImageField(serializers.ImageField):
    """ImageField that accepts either an uploaded file or a string (URL).

    If the incoming data is a string (URL or empty), the field will return the
    string unchanged so the serializer update logic can decide how to handle it
    (ignore, keep existing, or clear).
    """

    def to_internal_value(self, data):
        # Allow string URLs or empty values to pass through without raising
        # the usual "not a file" error from ImageField.
        if isinstance(data, str):
            return data
        return super().to_internal_value(data)


class PermissionSerializer(serializers.ModelSerializer):
    """Permission serializer"""

    app_label = serializers.CharField(source="content_type.app_label", read_only=True)
    model = serializers.CharField(source="content_type.model", read_only=True)
    content_type_name = serializers.CharField(
        source="content_type.name", read_only=True
    )

    class Meta:
        model = Permission
        fields = ["id", "name", "codename", "app_label", "model", "content_type_name"]


class PermissionCreateSerializer(serializers.ModelSerializer):
    """Permission serializer for create operations"""

    app_label = serializers.CharField(write_only=True, required=True)
    model = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = Permission
        fields = ["name", "codename", "app_label", "model"]

    def create(self, validated_data):
        from django.contrib.contenttypes.models import ContentType

        app_label = validated_data.pop("app_label")
        model = validated_data.pop("model")

        try:
            content_type = ContentType.objects.get(app_label=app_label, model=model)
        except ContentType.DoesNotExist:
            raise serializers.ValidationError(
                f"Content type for app '{app_label}' and model '{model}' does not exist."
            )

        # Check if permission already exists
        if Permission.objects.filter(
            codename=validated_data["codename"], content_type=content_type
        ).exists():
            raise serializers.ValidationError(
                "A permission with this codename already exists for this content type."
            )

        return Permission.objects.create(content_type=content_type, **validated_data)


class PermissionUpdateSerializer(serializers.ModelSerializer):
    """Permission serializer for update operations"""

    app_label = serializers.CharField(read_only=True, source="content_type.app_label")
    model = serializers.CharField(read_only=True, source="content_type.model")

    class Meta:
        model = Permission
        fields = ["id", "name", "codename", "app_label", "model"]
        read_only_fields = [
            "codename",
            "app_label",
            "model",
        ]  # Codename and content type cannot be changed


class PermissionListSerializer(serializers.ModelSerializer):
    """Permission serializer for list views"""

    app_label = serializers.CharField(source="content_type.app_label", read_only=True)
    model = serializers.CharField(source="content_type.model", read_only=True)
    content_type_name = serializers.CharField(
        source="content_type.name", read_only=True
    )

    class Meta:
        model = Permission
        fields = ["id", "name", "codename", "app_label", "model", "content_type_name"]


class UserPermissionUpdateSerializer(serializers.Serializer):
    """Serializer for updating user permissions"""

    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=True,
        help_text="List of permission codenames to assign to the user",
    )

    def validate_permissions(self, value):
        """Validate that all provided permissions exist"""
        from django.contrib.auth.models import Permission

        existing_codenames = set(Permission.objects.values_list("codename", flat=True))
        invalid_permissions = [perm for perm in value if perm not in existing_codenames]
        if invalid_permissions:
            raise serializers.ValidationError(
                f"Invalid permissions: {', '.join(invalid_permissions)}"
            )
        return value


# User Role Serializers
class UserRoleListSerializer(serializers.ModelSerializer):
    """User role serializer for list views"""

    permissions_count = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()

    class Meta:
        model = UserRole
        fields = [
            "id",
            "name",
            "display_name",
            "description",
            "is_active",
            "permissions_count",
            "users_count",
            "created_at",
        ]

    @extend_schema_field(serializers.IntegerField)
    def get_permissions_count(self, obj) -> int:
        return obj.permissions.count()

    @extend_schema_field(serializers.IntegerField)
    def get_users_count(self, obj) -> int:
        return obj.users.count()


class UserRoleDetailSerializer(serializers.ModelSerializer):
    """User role serializer for detail views"""

    permissions = PermissionSerializer(many=True, read_only=True)
    permissions_count = serializers.SerializerMethodField()
    users_count = serializers.SerializerMethodField()

    class Meta:
        model = UserRole
        fields = [
            "id",
            "name",
            "display_name",
            "description",
            "permissions",
            "permissions_count",
            "users_count",
            "is_active",
            "created_at",
        ]

    @extend_schema_field(serializers.IntegerField)
    def get_permissions_count(self, obj) -> int:
        return obj.permissions.count()

    @extend_schema_field(serializers.IntegerField)
    def get_users_count(self, obj) -> int:
        return obj.users.count()


class UserRoleCreateSerializer(serializers.ModelSerializer):
    """User role serializer for create operations"""

    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        write_only=True,
        help_text="List of permission codenames to assign to this role",
    )

    class Meta:
        model = UserRole
        fields = ["name", "description", "permissions", "is_active"]

    def create(self, validated_data):
        permissions = validated_data.pop("permissions", [])
        role = super().create(validated_data)
        if permissions:
            RoleService.update_role_permissions(role, permissions)
        return role


class UserRoleUpdateSerializer(serializers.ModelSerializer):
    """User role serializer for update operations"""

    permissions = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        write_only=True,
        help_text="List of permission codenames to assign to this role",
    )

    class Meta:
        model = UserRole
        fields = ["name", "description", "permissions", "is_active"]

    def update(self, instance, validated_data):
        permissions = validated_data.pop("permissions", None)
        role = super().update(instance, validated_data)
        if permissions is not None:
            RoleService.update_role_permissions(role, permissions)
        return role


# User Serializers
class UserListSerializer(serializers.ModelSerializer):
    """User serializer for list views"""

    role_display = serializers.CharField(source="role.display_name", read_only=True)
    full_name = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    is_staff_member = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "username",
            "full_name",
            "profile_picture",
            "role_display",
            "is_active",
            "is_approved",
            "is_verified",
            "is_staff",
            "profile_complete",
            "location",
            "is_staff_member",
            "last_login",
            "created_at",
        )

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj) -> str:
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_location(self, obj) -> str:
        return ""  # Not implemented

    @extend_schema_field(serializers.BooleanField)
    def get_is_staff_member(self, obj) -> bool:
        return obj.is_staff


    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_profile_picture(self, obj: User) -> str:
        """Get profile picture URL"""
        if obj.profile_image:
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(obj.profile_image.url)
            return obj.profile_image.url
        return ""


class UserDetailSerializer(serializers.ModelSerializer):
    """User serializer for detail views"""

    role_name = serializers.CharField(source="role.name", read_only=True)
    role_display = serializers.CharField(source="role.display_name", read_only=True)
    full_name = serializers.SerializerMethodField()
    location = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    permissions = PermissionSerializer(
        many=True, read_only=True, source="user_permissions"
    )
    role_permissions = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()
    date_of_birth = serializers.SerializerMethodField()
    profile_picture = serializers.SerializerMethodField()
    ward = serializers.SerializerMethodField()
    constituency = serializers.SerializerMethodField()
    county = serializers.SerializerMethodField()
    last_login_ip = serializers.CharField(read_only=True, required=False)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "username",
            "first_name",
            "last_name",
            "full_name",
            "phone_number",
            "user_id",
            "date_of_birth",
            "profile_picture",
            "profile_image",
            "ward",
            "constituency",
            "county",
            "location",
            "role",
            "role_name",
            "role_display",
            "is_active",
            "is_approved",
            "is_verified",
            "is_staff",
            "is_superuser",
            "must_change_password",
            "password_changed_at",
            "failed_login_attempts",
            "account_locked_until",
            "last_login_ip",
            "profile_complete",
            "profile_completed_at",
            "terms_accepted",
            "otp_device",
            "backup_codes",
            "profile",
            "permissions",
            "role_permissions",
            "date_joined",
            "created_at",
            "updated_at",
            "last_login",
        ]

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj) -> str:
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_location(self, obj) -> str:
        return ""  # Not implemented

    @extend_schema_field(serializers.DictField)
    def get_profile(self, obj) -> Optional[Dict[str, Any]]:
        if hasattr(obj, "profile"):
            return UserProfileListSerializer(obj.profile).data
        return None

    @extend_schema_field(serializers.DictField)
    def get_role_permissions(self, obj) -> dict:
        if obj.role:
            permissions = obj.role.permissions.select_related("content_type").all()
            grouped = {}
            for perm in permissions:
                app_label = perm.content_type.app_label
                if app_label not in grouped:
                    grouped[app_label] = []
                grouped[app_label].append(perm.codename)
            return grouped
        return {}

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_phone_number(self, obj: User) -> str:
        """Get phone number from user profile"""
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ""

    @extend_schema_field(serializers.DateField(allow_null=True))
    def get_date_of_birth(self, obj: User) -> Optional[str]:
        """Get date of birth (not implemented yet)"""
        return None

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_profile_picture(self, obj: User) -> str:
        """Get profile picture URL"""
        if obj.profile_image:
            request = self.context.get("request")
            if request:
                return request.build_absolute_uri(obj.profile_image.url)
            return obj.profile_image.url
        return ""

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_ward(self, obj: User) -> str:
        """Get ward (not implemented yet)"""
        return ""

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_constituency(self, obj: User) -> str:
        """Get constituency (not implemented yet)"""
        return ""

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_county(self, obj: User) -> str:
        """Get county (not implemented yet)"""
        return ""


class UserPermissionResponseSerializer(serializers.Serializer):
    """Serializer for user permission update response"""

    message = serializers.CharField()
    user = UserDetailSerializer()
    added_permissions = serializers.ListField(child=serializers.CharField())
    removed_permissions = serializers.ListField(child=serializers.CharField())


class UserCreateSerializer(serializers.ModelSerializer):
    """User serializer for create operations"""
    password = serializers.CharField(write_only=True, required=False, allow_null=True)
    role_name = serializers.ChoiceField(
        choices=UserRoleConstants.ROLE_CHOICES,
        write_only=True,
        required=False,
        default=UserRoleConstants.DEFAULT_ROLE,
        help_text="Role to assign to the user. Valid choices: admin"
    )
    phone_number = serializers.CharField(
        write_only=True, allow_blank=True
    )
    profile_image = FlexibleImageField(required=False, allow_null=True)
    first_name = serializers.CharField(required=True, help_text="First name of the user")
    last_name = serializers.CharField(required=True, help_text="Last name of the user")
    id = serializers.CharField(required=False, allow_blank=True, help_text="Optional custom user ID. If not provided, auto-generated.")

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "password",
            "first_name",
            "last_name",
            "phone_number",
            "role_name",
            "is_active",
            "is_approved",
            "is_verified",
            "must_change_password",
            "is_staff",
            "terms_accepted",
            "profile_image",
        ]

    def create(self, validated_data):
        role_name = validated_data.pop("role_name")
        password = validated_data.pop("password", None)
        phone_number = validated_data.pop("phone_number", "")
        profile_image = validated_data.pop("profile_image", None)
        user_id = validated_data.pop("id", None)  # Extract optional user ID (user-provided takes priority) 
        email = validated_data.pop("email")
        first_name = validated_data.pop("first_name")
        last_name = validated_data.pop("last_name")
        
        # Remove any remaining None values from validated_data to prevent passing them to the model
        validated_data = {k: v for k, v in validated_data.items() if v is not None}

        # Set the ID if provided by user (takes priority over auto-generation)
        if user_id:
            validated_data["id"] = user_id

        # Get or create role if needed
        role = None
        if role_name:
            from .models import UserRole
            role = UserRole.objects.filter(name=role_name).first()

        # Create user instance with email, password, and all extra fields
        user = User(
            email=email,
            first_name=first_name,
            last_name=last_name,
            role=role,
            **validated_data
        )
        user.set_password(password)
        user.save()  # This will call the custom save() which handles ID auto-generation

        # Ensure user profile exists (signal handler creates it, but use get_or_create for safety)
        from .models import UserProfile
        UserProfile.objects.get_or_create(
            user=user,
            defaults={
                "bio": f"Profile for {user.get_full_name() or user.email}",
                "preferred_language": "en",
                "allow_notifications": True,
            }
        )

        # Handle profile image if provided (only if an actual uploaded file)
        if profile_image:
            # If frontend sent a URL string (existing image), ignore it here.
            if not isinstance(profile_image, str):
                user.profile_image = profile_image
                user.save(update_fields=["profile_image"])

        # Update user profile with additional data
        if hasattr(user, 'profile') and phone_number:
            user.profile.phone_number = phone_number
            user.profile.save()

        return user

    def validate_role_name(self, value):
        """
        Validate that the role_name is a valid role that exists or can be created.
        Valid roles must be from UserRoleConstants.ROLE_CHOICES.
        """
        if not value:
            # If no role provided, use default
            return UserRoleConstants.DEFAULT_ROLE
        
        # Check if role is in valid choices
        valid_roles = [choice[0] for choice in UserRoleConstants.ROLE_CHOICES]
        if value not in valid_roles:
            raise serializers.ValidationError(
                f"Invalid role '{value}'. Valid roles are: {', '.join(valid_roles)}"
            )
        
        # Verify role exists in database, create if necessary
        try:
            UserRole.objects.get(name=value)
        except UserRole.DoesNotExist:
            # Auto-create missing role with default settings
            role_display = dict(UserRoleConstants.ROLE_CHOICES).get(
                value, value.replace("_", " ").title()
            )
            UserRole.objects.create(
                name=value,
                display_name=role_display,
                description=f"Auto-created {value} role",
                is_active=True,
            )
        
        return value


class UserUpdateSerializer(serializers.ModelSerializer):
    """User serializer for update operations"""

    role_name = serializers.ChoiceField(
        choices=UserRoleConstants.ROLE_CHOICES,
        write_only=True,
        required=False,
        help_text="Role to assign to the user. Valid choices: admin"
    )
    phone_number = serializers.CharField(required=False, allow_blank=True)
    user_id = serializers.CharField(required=False, allow_blank=True)
    date_of_birth = serializers.DateField(required=False, allow_null=True)
    ward = serializers.CharField(required=False, allow_blank=True)
    constituency = serializers.CharField(required=False, allow_blank=True)
    county = serializers.CharField(required=False, allow_blank=True)
    profile_image = FlexibleImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "phone_number",
            "user_id",
            "date_of_birth",
            "ward",
            "constituency",
            "county",
            "role_name",
            "is_active",
            "is_approved",
            "is_verified",
            "must_change_password",
            "profile_image",
            "profile_complete",
        ]

    def update(self, instance, validated_data):
        from django.utils import timezone
        
        role_name = validated_data.pop("role_name", None)
        # Extract profile_image separately so we can handle URLs vs uploaded files
        profile_image_value = validated_data.pop("profile_image", None)

        # Handle profile fields
        profile_fields = [
            "phone_number",
            "user_id",
            "date_of_birth",
            "ward",
            "constituency",
            "county",
        ]
        profile_data = {}
        for field in profile_fields:
            if field in validated_data:
                profile_data[field] = validated_data.pop(field)

        # Update user core fields first (without profile_image)
        user = super().update(instance, validated_data)

        # Update profile if needed
        if profile_data:
            profile, created = UserProfile.objects.get_or_create(user=user)
            for field, value in profile_data.items():
                if value is not None:
                    setattr(profile, field, value)
            profile.save()

        # Handle profile image value (file or string/URL)
        # If a file-like object was provided, assign it to the user and save.
        # If a string/URL was provided (frontend sent existing URL), ignore it
        # to avoid the "not a file" validation error and unnecessary updates.
        if profile_image_value is not None and profile_image_value != "":
            # If it's a string, assume it's a URL or existing value and skip
            if isinstance(profile_image_value, str):
                # nothing to do; frontend likely sent existing URL
                pass
            else:
                # Treat as uploaded file
                user.profile_image = profile_image_value
                try:
                    user.save(update_fields=["profile_image"])
                except Exception:
                    # If save fails, raise so caller sees the error
                    raise

            # Mark profile as complete if profile image was uploaded
            if not user.profile_complete and not isinstance(profile_image_value, str):
                user.profile_complete = True
                user.profile_completed_at = timezone.now()
                user.save(update_fields=["profile_complete", "profile_completed_at"])

        if role_name and (not user.role or user.role.name != role_name):
            # Use service to change role and create audit record. The service
            # returns a boolean; refresh user from DB after a successful change.
            try:
                success = UserService.change_user_role(
                    user=user,
                    new_role_name=role_name,
                    changed_by=self.context["request"].user,
                )
                if success:
                    # refresh from database to get updated role relation
                    user.refresh_from_db()
            except Exception:
                # Let any exceptions bubble; this will result in a 500 and
                # surface the error to the caller which is preferable to
                # silently failing to update the role.
                raise

        return user

    def validate_role_name(self, value):
        """
        Validate that the role_name is a valid role that exists or can be created.
        Valid roles must be from UserRoleConstants.ROLE_CHOICES.
        """
        if not value:
            # If no role provided, skip update
            return None
        
        # Check if role is in valid choices
        valid_roles = [choice[0] for choice in UserRoleConstants.ROLE_CHOICES]
        if value not in valid_roles:
            raise serializers.ValidationError(
                f"Invalid role '{value}'. Valid roles are: {', '.join(valid_roles)}"
            )
        
        # Verify role exists in database, create if necessary
        try:
            UserRole.objects.get(name=value)
        except UserRole.DoesNotExist:
            # Auto-create missing role with default settings
            role_display = dict(UserRoleConstants.ROLE_CHOICES).get(
                value, value.replace("_", " ").title()
            )
            UserRole.objects.create(
                name=value,
                display_name=role_display,
                description=f"Auto-created {value} role",
                is_active=True,
            )
        
        return value


# User Profile Serializers
class UserProfileListSerializer(serializers.ModelSerializer):
    """User profile serializer for list views"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            "id",
            "user_email",
            "user_name",
            "preferred_language",
            "show_email",
            "show_phone",
            "allow_notifications",
            "created_at",
            "updated_at",
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()


class UserProfileDetailSerializer(serializers.ModelSerializer):
    """User profile serializer for detail views"""

    user = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = [
            "id",
            "user",
            "bio",
            "preferred_language",
            "show_email",
            "show_phone",
            "allow_notifications",
            "interface_theme",
            "created_at",
            "updated_at",
        ]

    @extend_schema_field(serializers.DictField)
    def get_user(self, obj) -> Dict[str, Any]:
        return {
            "id": obj.user.id,
            "email": obj.user.email,
            "full_name": obj.user.get_full_name(),
            "role": obj.user.role.display_name if obj.user.role else None,
        }


class UserProfileCreateSerializer(serializers.ModelSerializer):
    """User profile serializer for create operations"""

    class Meta:
        model = UserProfile
        fields = [
            "bio",
            "preferred_language",
            "show_email",
            "show_phone",
            "allow_notifications",
            "interface_theme",
        ]


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """User profile serializer for update operations"""

    class Meta:
        model = UserProfile
        fields = [
            "bio",
            "preferred_language",
            "show_email",
            "show_phone",
            "allow_notifications",
            "interface_theme",
        ]


# User Role History Serializer
class UserRoleHistorySerializer(serializers.ModelSerializer):
    """User role history serializer"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.SerializerMethodField()
    old_role_display = serializers.CharField(
        source="old_role.get_name_display", read_only=True
    )
    new_role_display = serializers.CharField(
        source="new_role.get_name_display", read_only=True
    )
    changed_by_email = serializers.CharField(source="changed_by.email", read_only=True)
    changed_by_name = serializers.SerializerMethodField()

    class Meta:
        model = UserRoleHistory
        fields = [
            "id",
            "user_email",
            "user_name",
            "old_role_display",
            "new_role_display",
            "reason",
            "changed_by_email",
            "changed_by_name",
            "created_at",
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_changed_by_name(self, obj) -> str:
        return obj.changed_by.get_full_name() if obj.changed_by else ""


# User Session Serializer
class UserSessionSerializer(serializers.ModelSerializer):
    """User session serializer"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.SerializerMethodField()
    duration = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = UserSession
        fields = [
            "id",
            "user_email",
            "user_name",
            "ip_address",
            "user_agent",
            "is_active",
            "created_at",
            "last_activity",
            "duration",
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name()

    @extend_schema_field(serializers.BooleanField)
    def get_is_active(self, obj) -> bool:
        return obj.is_active

    @extend_schema_field(serializers.DurationField)
    def get_duration(self, obj) -> Optional[str]:
        if obj.last_activity and obj.created_at:
            return str(obj.last_activity - obj.created_at)
        return None


# Login Attempt Serializer
class LoginAttemptSerializer(serializers.ModelSerializer):
    """Login attempt serializer"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_name = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = LoginAttempt
        fields = [
            "id",
            "user_email",
            "user_name",
            "ip_address",
            "user_agent",
            "success",
            "created_at",
        ]

    @extend_schema_field(serializers.CharField)
    def get_user_name(self, obj) -> str:
        return obj.user.get_full_name() if obj.user else ""


# Management Serializers (for admin operations)
class UserManagementSerializer(UserDetailSerializer):
    """User management serializer for admin operations"""

    pass


# API Response Serializers
class UserPermissionsSerializer(serializers.Serializer):
    """User permissions response serializer"""

    user_id = serializers.IntegerField()
    role = serializers.CharField(allow_null=True)
    permissions = serializers.ListField(child=serializers.CharField())
    is_staff = serializers.BooleanField()
    is_supervisor = serializers.BooleanField()
    is_admin = serializers.BooleanField()


class UserRoleChangeRequestSerializer(serializers.Serializer):
    """User role change request serializer"""

    role_name = serializers.CharField(max_length=50)


class UserRoleChangeResponseSerializer(serializers.Serializer):
    """User role change response serializer"""

    message = serializers.CharField()
    user = UserDetailSerializer()


class UserApprovalSerializer(serializers.Serializer):
    """User approval response serializer"""

    message = serializers.CharField()


class SocialAuthURLSerializer(serializers.Serializer):
    """Social authentication URLs serializer"""

    google = serializers.URLField(allow_null=True)
    github = serializers.URLField(allow_null=True)
    facebook = serializers.URLField(allow_null=True)


class UserDetailsSerializer(serializers.ModelSerializer):
    """User details serializer for dj-rest-auth"""

    role = UserRoleDetailSerializer(read_only=True)
    full_name = serializers.SerializerMethodField()
    profile = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "phone_number",
            "user_id",
            "role",
            "is_verified",
            "is_approved",
            "created_at",
            "last_login",
            "profile",
            "profile_image",
        ]
        read_only_fields = [
            "id",
            "email",
            "is_verified",
            "is_approved",
            "created_at",
            "last_login",
        ]

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj: User) -> str:
        """Get user's full name"""
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField(allow_blank=True))
    def get_phone_number(self, obj: User) -> str:
        """Get phone number from user profile"""
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ""

    @extend_schema_field(serializers.DictField(allow_null=True))
    def get_profile(self, obj: User) -> Optional[Dict[str, Any]]:
        """Get user profile details"""
        try:
            profile = obj.profile
            return {
                "bio": profile.bio,
                "preferred_language": profile.preferred_language,
            }
        except UserProfile.DoesNotExist:
            return None


class CustomJWTSerializer(JWTSerializer):
    """Custom JWT serializer to include user role information"""

    user = UserDetailsSerializer(read_only=True)


class UserManagementSerializer(serializers.ModelSerializer):
    """Serializer for user management by admins"""

    role_name = serializers.CharField(write_only=True, required=False)
    role = UserRoleListSerializer(read_only=True, allow_null=True)
    full_name = serializers.SerializerMethodField()
    user_id = serializers.SerializerMethodField()
    phone_number = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "user_id",
            "phone_number",
            "role",
            "role_name",
            "is_active",
            "is_approved",
            "is_verified",
            "created_at",
            "last_login",
            "failed_login_attempts",
            "account_locked_until",
            "password_changed_at",
            "must_change_password",
        ]
        read_only_fields = [
            "email",
            "created_at",
            "last_login",
            "failed_login_attempts",
            "account_locked_until",
            "password_changed_at",
        ]

    @extend_schema_field(serializers.CharField)
    def get_full_name(self, obj) -> str:
        return obj.get_full_name()

    @extend_schema_field(serializers.CharField)
    def get_user_id(self, obj) -> str:
        # Backwards compatible: support legacy employee_id attr
        return getattr(obj, 'user_id', getattr(obj, 'employee_id', None))


    @extend_schema_field(serializers.CharField)
    def get_phone_number(self, obj) -> str:
        try:
            return obj.profile.phone_number
        except UserProfile.DoesNotExist:
            return ""


# Social Authentication Serializers
class SocialAuthURLSerializer(serializers.Serializer):
    """Serializer for social authentication URLs response"""

    google = serializers.URLField()
    github = serializers.URLField()
    facebook = serializers.URLField()


# API Response Serializers
class UserApprovalSerializer(serializers.Serializer):
    """Serializer for user approval response"""

    message = serializers.CharField()


class UserRoleChangeRequestSerializer(serializers.Serializer):
    """Serializer for role change request"""

    role_name = serializers.CharField(help_text="Name of the role to assign")


class UserRoleChangeResponseSerializer(serializers.Serializer):
    """Serializer for role change response"""

    message = serializers.CharField()
    user = UserManagementSerializer()


class UserPermissionsSerializer(serializers.Serializer):
    """Serializer for user permissions response"""

    id = serializers.IntegerField()
    role = serializers.CharField(allow_null=True)
    permissions = serializers.ListField(child=serializers.CharField())
    is_staff = serializers.BooleanField()
    is_supervisor = serializers.BooleanField()
    is_admin = serializers.BooleanField()


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile management"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.CharField(source="user.full_name", read_only=True)

    class Meta:
        model = UserProfile
        fields = [
            "id",
            "user",
            "user_email",
            "user_full_name",
            "bio",
            "preferred_language",
            "show_email",
            "show_phone",
            "allow_notifications",
            "interface_theme",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class UserRoleHistorySerializer(serializers.ModelSerializer):
    """Serializer for user role history"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.CharField(source="user.full_name", read_only=True)
    old_role_name = serializers.CharField(source="old_role.name", read_only=True)
    old_role_display = serializers.CharField(
        source="old_role.get_name_display", read_only=True
    )
    new_role_name = serializers.CharField(source="new_role.name", read_only=True)
    new_role_display = serializers.CharField(
        source="new_role.get_name_display", read_only=True
    )
    changed_by_email = serializers.CharField(source="changed_by.email", read_only=True)
    changed_by_name = serializers.CharField(
        source="changed_by.full_name", read_only=True
    )

    class Meta:
        model = UserRoleHistory
        fields = [
            "id",
            "user",
            "user_email",
            "user_full_name",
            "old_role",
            "old_role_name",
            "old_role_display",
            "new_role",
            "new_role_name",
            "new_role_display",
            "changed_by",
            "changed_by_email",
            "changed_by_name",
            "reason",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class UserSessionSerializer(serializers.ModelSerializer):
    """Serializer for user session management"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.SerializerMethodField()
    is_expired = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()
    risk_score = serializers.SerializerMethodField()
    is_current_session = serializers.SerializerMethodField()
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = UserSession
        fields = [
            "id",
            "user",
            "user_email",
            "user_full_name",
            "session_key",
            "ip_address",
            "user_agent",
            "is_active",
            "expires_at",
            "device_type",
            "device_os",
            "browser",
            "location_info",
            "device_info",
            "last_activity",
            "is_expired",
            "is_current_session",
            "risk_score",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    @extend_schema_field(serializers.CharField)
    def get_user_full_name(self, obj) -> str:
        return obj.user.get_full_name()

    @extend_schema_field(serializers.BooleanField)
    def get_is_expired(self, obj) -> bool:
        return obj.is_expired()

    @extend_schema_field(serializers.BooleanField)
    def get_is_active(self, obj) -> bool:
        return obj.is_active

    @extend_schema_field(serializers.FloatField)
    def get_risk_score(self, obj) -> float:
        return obj.risk_score

    @extend_schema_field(serializers.BooleanField)
    def get_is_current_session(self, obj) -> bool:
        request = self.context.get("request")
        if request and hasattr(request, "session"):
            return obj.session_key == request.session.session_key
        return False


class LoginAttemptSerializer(serializers.ModelSerializer):
    """Serializer for login attempt tracking"""

    user_email = serializers.CharField(source="user.email", read_only=True)
    user_full_name = serializers.CharField(source="user.full_name", read_only=True)
    ip_address = serializers.CharField(read_only=True)

    class Meta:
        model = LoginAttempt
        fields = [
            "id",
            "user",
            "user_email",
            "user_full_name",
            "email",
            "ip_address",
            "success",
            "user_agent",
            "failure_reason",
            "location_info",
            "device_type",
            "device_os",
            "browser",
            "session_id",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class PermissionDetailSerializer(serializers.ModelSerializer):
    """Enhanced permission serializer for entity manager"""

    app_label = serializers.CharField(source="content_type.app_label", read_only=True)
    model = serializers.CharField(source="content_type.model", read_only=True)
    content_type_name = serializers.CharField(
        source="content_type.name", read_only=True
    )

    class Meta:
        model = Permission
        fields = ["id", "name", "codename", "app_label", "model", "content_type_name"]
        read_only_fields = ["id"]


class PermissionUpdateRequestSerializer(serializers.Serializer):
    """Serializer for updating user permissions"""

    permissions = serializers.ListField(
        child=serializers.DictField(),
        help_text="List of permissions to grant or revoke",
    )
    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=500,
        help_text="Optional notes for the permission change",
    )

    def validate_permissions(self, value):
        """Validate permissions format"""
        for perm in value:
            if not isinstance(perm, dict):
                raise serializers.ValidationError(
                    "Each permission must be a dictionary"
                )
            if "permission_id" not in perm:
                raise serializers.ValidationError(
                    "Each permission must have a 'permission_id' field"
                )
            if "granted" not in perm:
                raise serializers.ValidationError(
                    "Each permission must have a 'granted' field"
                )
            if not isinstance(perm["granted"], bool):
                raise serializers.ValidationError("'granted' field must be a boolean")
        return value


class UserApprovalRequestSerializer(serializers.Serializer):
    """Serializer for user approval requests"""

    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=500,
        help_text="Optional notes for the approval",
    )


class RoleChangeRequestSerializer(serializers.Serializer):
    """Serializer for role change requests"""

    role_name = serializers.CharField(
        max_length=100, help_text="Name of the role to assign"
    )
    notes = serializers.CharField(
        required=False,
        allow_blank=True,
        max_length=500,
        help_text="Optional notes for the role change",
    )
