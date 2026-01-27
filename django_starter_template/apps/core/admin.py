from django.contrib import admin
from .models import TimestampedModel, AuditMixin, SoftDeleteMixin, BaseModel
from django.contrib.auth.models import Permission
from django.contrib.admin.models import LogEntry
from django.utils.html import format_html
from django.urls import reverse
 

# Note: These are abstract base models, so they don't get registered directly
# They are used as mixins for other models


class TimestampedModelAdmin(admin.ModelAdmin):
    """
    Base admin class for models that inherit from TimestampedModel
    """

    readonly_fields = ("created_at", "updated_at")

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        if hasattr(self.model, "created_at") or hasattr(self.model, "updated_at"):
            # Add timestamps section if not already present
            timestamp_fields = []
            if hasattr(self.model, "created_at"):
                timestamp_fields.append("created_at")
            if hasattr(self.model, "updated_at"):
                timestamp_fields.append("updated_at")

            if timestamp_fields:
                fieldsets = list(fieldsets) if fieldsets else []
                fieldsets.append(
                    (
                        "Timestamps",
                        {"fields": tuple(timestamp_fields), "classes": ("collapse",)},
                    )
                )
        return tuple(fieldsets) if fieldsets else None


class AuditMixinAdmin(TimestampedModelAdmin):
    """
    Base admin class for models that inherit from AuditMixin
    """

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = list(super().get_readonly_fields(request, obj))
        audit_fields = ["created_by", "updated_by"]
        for field in audit_fields:
            if hasattr(self.model, field) and field not in readonly_fields:
                readonly_fields.append(field)
        return readonly_fields

    def save_model(self, request, obj, form, change):
        """
        Automatically set created_by and updated_by fields
        """
        if not change:  # Creating new object
            if hasattr(obj, "created_by"):
                obj.created_by = request.user
        if hasattr(obj, "updated_by"):
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)


class SoftDeleteMixinAdmin(admin.ModelAdmin):
    """
    Base admin class for models that inherit from SoftDeleteMixin
    """

    list_display = ("__str__", "is_deleted")
    list_filter = ("is_deleted",)

    def get_queryset(self, request):
        """
        Show all objects including soft-deleted ones in admin
        """
        if hasattr(self.model, "all_objects"):
            return self.model.all_objects.get_queryset()
        return super().get_queryset(request)

    actions = ["soft_delete_selected", "restore_selected"]

    def soft_delete_selected(self, request, queryset):
        """
        Soft delete selected objects
        """
        count = 0
        for obj in queryset:
            if hasattr(obj, "soft_delete") and not obj.is_deleted:
                obj.soft_delete()
                count += 1

        self.message_user(request, f"{count} object(s) were soft deleted.")

    soft_delete_selected.short_description = "Soft delete selected items"

    def restore_selected(self, request, queryset):
        """
        Restore selected soft-deleted objects
        """
        count = 0
        for obj in queryset:
            if hasattr(obj, "restore") and obj.is_deleted:
                obj.restore()
                count += 1

        self.message_user(request, f"{count} object(s) were restored.")

    restore_selected.short_description = "Restore selected items"


class BaseModelAdmin(AuditMixinAdmin, SoftDeleteMixinAdmin):
    """
    Combined admin class for models that inherit from BaseModel
    """

    pass


class PermissionAdmin(admin.ModelAdmin):
    """
    Admin class for Permission model to enhance usability
    """

    list_display = ("name", "codename", "content_type")
    search_fields = ("name", "codename")
    list_filter = ("content_type",)
    ordering = ("content_type__app_label", "codename")
    actions = ["delete_selected_permissions"]

    def delete_selected_permissions(self, request, queryset):
        """
        Custom action to delete selected permissions
        """
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f"Successfully deleted {count} permission(s).")

    delete_selected_permissions.short_description = "Delete selected permissions"


# Permission is already registered by Django admin
# admin.site.register(Permission, PermissionAdmin)

# System Settings Admin
from .models import SystemSettings


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    """Admin interface for System Settings"""

    list_display = ["site_name", "maintenance_mode", "updated_at", "updated_by"]
    readonly_fields = ["updated_at"]

    fieldsets = (
        (
            "General Settings",
            {
                "fields": (
                    "site_name",
                    "site_url",
                    "timezone",
                    "date_format",
                    "time_format",
                )
            },
        ),
        (
            "Security Settings",
            {
                "fields": (
                    "session_timeout",
                    "max_login_attempts",
                    "password_min_length",
                    "require_2fa",
                    "allow_user_registration",
                )
            },
        ),
        (
            "Email Settings",
            {
                "fields": (
                    "email_from_name",
                    "email_from_address",
                    "smtp_host",
                    "smtp_port",
                    "smtp_use_tls",
                )
            },
        ),
        (
            "Notification Settings",
            {
                "fields": (
                    "enable_email_notifications",
                    "enable_push_notifications",
                    "notification_retention_days",
                )
            },
        ),
        (
            "System Settings",
            {
                "fields": (
                    "maintenance_mode",
                    "debug_mode",
                    "log_level",
                    "cache_enabled",
                )
            },
        ),
        ("Metadata", {"fields": ("updated_at", "updated_by")}),
    )

    def has_add_permission(self, request):
        """Only one instance allowed (singleton)"""
        return not SystemSettings.objects.exists()

    def has_delete_permission(self, request, obj=None):
        """Prevent deletion"""
        return False


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    """Admin for Django's LogEntry model with useful read-only listing and links

    This admin exposes a compact view of admin log entries and provides a
    clickable link to the related object's change page when possible.
    """

    list_display = (
        "action_time",
        "user",
        "content_type",
        "object_link",
        "action_flag",
        "change_message",
    )
    search_fields = ("object_repr", "change_message", "user__username")
    list_filter = ("action_flag", "content_type", "user")
    readonly_fields = (
        "action_time",
        "user",
        "content_type",
        "object_id",
        "object_repr",
        "change_message",
    )
    date_hierarchy = "action_time"
    ordering = ("-action_time",)

    def has_add_permission(self, request):
        # Log entries are read-only and created by the admin framework
        return False

    def has_change_permission(self, request, obj=None):
        # Prevent editing of log entries via admin
        return False

    def object_link(self, obj):
        """Return a link to the related object's admin change page when available."""
        if obj.content_type_id and obj.object_id:
            try:
                app_label = obj.content_type.app_label
                model = obj.content_type.model
                url_name = f"admin:{app_label}_{model}_change"
                url = reverse(url_name, args=(obj.object_id,))
                return format_html('<a href="{}">{}</a>', url, obj.object_repr)
            except Exception:
                # Fall back to plain text when reverse fails (object deleted or no permission)
                return obj.object_repr
        return obj.object_repr

    object_link.short_description = "object"
    