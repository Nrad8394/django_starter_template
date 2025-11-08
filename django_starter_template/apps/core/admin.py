from django.contrib import admin
from .models import TimestampedModel, AuditMixin, SoftDeleteMixin, BaseModel
from django.contrib.auth.models import Permission

# Note: These are abstract base models, so they don't get registered directly
# They are used as mixins for other models

class TimestampedModelAdmin(admin.ModelAdmin):
    """
    Base admin class for models that inherit from TimestampedModel
    """
    readonly_fields = ('created_at', 'updated_at')

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        if hasattr(self.model, 'created_at') or hasattr(self.model, 'updated_at'):
            # Add timestamps section if not already present
            timestamp_fields = []
            if hasattr(self.model, 'created_at'):
                timestamp_fields.append('created_at')
            if hasattr(self.model, 'updated_at'):
                timestamp_fields.append('updated_at')

            if timestamp_fields:
                fieldsets = list(fieldsets) if fieldsets else []
                fieldsets.append(
                    ('Timestamps', {
                        'fields': tuple(timestamp_fields),
                        'classes': ('collapse',)
                    })
                )
        return tuple(fieldsets) if fieldsets else None


class AuditMixinAdmin(TimestampedModelAdmin):
    """
    Base admin class for models that inherit from AuditMixin
    """
    def get_readonly_fields(self, request, obj=None):
        readonly_fields = list(super().get_readonly_fields(request, obj))
        audit_fields = ['created_by', 'updated_by']
        for field in audit_fields:
            if hasattr(self.model, field) and field not in readonly_fields:
                readonly_fields.append(field)
        return readonly_fields

    def save_model(self, request, obj, form, change):
        """
        Automatically set created_by and updated_by fields
        """
        if not change:  # Creating new object
            if hasattr(obj, 'created_by'):
                obj.created_by = request.user
        if hasattr(obj, 'updated_by'):
            obj.updated_by = request.user
        super().save_model(request, obj, form, change)


class SoftDeleteMixinAdmin(admin.ModelAdmin):
    """
    Base admin class for models that inherit from SoftDeleteMixin
    """
    list_display = ('__str__', 'is_deleted')
    list_filter = ('is_deleted',)

    def get_queryset(self, request):
        """
        Show all objects including soft-deleted ones in admin
        """
        if hasattr(self.model, 'all_objects'):
            return self.model.all_objects.get_queryset()
        return super().get_queryset(request)

    actions = ['soft_delete_selected', 'restore_selected']

    def soft_delete_selected(self, request, queryset):
        """
        Soft delete selected objects
        """
        count = 0
        for obj in queryset:
            if hasattr(obj, 'soft_delete') and not obj.is_deleted:
                obj.soft_delete()
                count += 1

        self.message_user(
            request,
            f'{count} object(s) were soft deleted.'
        )
    soft_delete_selected.short_description = "Soft delete selected items"

    def restore_selected(self, request, queryset):
        """
        Restore selected soft-deleted objects
        """
        count = 0
        for obj in queryset:
            if hasattr(obj, 'restore') and obj.is_deleted:
                obj.restore()
                count += 1

        self.message_user(
            request,
            f'{count} object(s) were restored.'
        )
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
    list_display = ('name', 'codename', 'content_type')
    search_fields = ('name', 'codename')
    list_filter = ('content_type',)
    ordering = ('content_type__app_label', 'codename')
    actions = ['delete_selected_permissions']
    def delete_selected_permissions(self, request, queryset):
        """
        Custom action to delete selected permissions
        """
        count = queryset.count()
        queryset.delete()
        self.message_user(request, f'Successfully deleted {count} permission(s).')
    delete_selected_permissions.short_description = "Delete selected permissions"

# Permission is already registered by Django admin
# admin.site.register(Permission, PermissionAdmin)