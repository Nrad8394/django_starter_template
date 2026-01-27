import uuid
from django.db import models
from django.utils import timezone


class TimestampedModel(models.Model):
    """Abstract base class with timestamp fields"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class AuditMixin(models.Model):
    """Mixin to track who created/modified records"""

    created_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_created",
    )
    updated_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_updated",
    )

    class Meta:
        abstract = True


class SoftDeleteMixin(models.Model):
    """Mixin for soft deletion"""

    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(class)s_deleted",
    )

    class Meta:
        abstract = True

    # def delete(self, using=None, keep_parents=False):
    #     """Soft delete implementation"""
    #     self.is_deleted = True
    #     self.deleted_at = timezone.now()
    #     self.save()

    def hard_delete(self):
        """Actual deletion from database"""
        super().delete()


class BaseModel(TimestampedModel, AuditMixin, SoftDeleteMixin):
    """Base model with all common functionality"""

    def rename_pk(self, new_pk):
        """Rename the primary key for this instance to `new_pk` while preserving
        related references.

        This performs an INSERT for a new instance with the provided PK, updates
        all ForeignKey references across all models to point to the new PK, moves
        any ManyToMany relations defined on this model, and then deletes the
        old instance. This is used to support editable external identifiers that
        were implemented as primary keys.

        WARNING: use with care; unique constraints on related models may raise
        IntegrityError if collisions occur.
        """
        from django.db import transaction, IntegrityError
        from django.apps import apps
        from django.db import models as dj_models

        pk_name = self._meta.pk.name
        old_pk = getattr(self, pk_name)
        if old_pk == new_pk:
            return self

        with transaction.atomic():
            # Collect field values for creating the new instance
            field_values = {}
            for f in self._meta.fields:
                if f.name == pk_name:
                    continue
                # Skip auto fields
                if getattr(f, 'auto_created', False):
                    continue
                field_values[f.name] = getattr(self, f.name)

            # Create new instance with the new pk
            field_values[pk_name] = new_pk
            NewClass = self.__class__
            new_instance = NewClass(**field_values)
            try:
                # force_insert to ensure we create a fresh row
                new_instance.save(force_insert=True)
            except IntegrityError:
                raise

            # Update ForeignKey references across all models
            for model in apps.get_models():
                for f in model._meta.fields:
                    if isinstance(f, dj_models.ForeignKey) and f.remote_field.model == NewClass:
                        # field stores the PK value; perform bulk update
                        lookup = {f.name: old_pk}
                        update = {f.name: new_pk}
                        model.objects.filter(**lookup).update(**update)

                # Handle ManyToMany fields defined on other models that point to this model
                for m2m in model._meta.many_to_many:
                    if m2m.remote_field.model == NewClass:
                        # For each object on the other model related to old instance,
                        # replace the relation to point to the new instance.
                        related_objs = model.objects.filter(**{m2m.name: old_pk})
                        for obj in related_objs:
                            getattr(obj, m2m.name).remove(self)
                            getattr(obj, m2m.name).add(new_instance)

            # Move ManyToMany relations defined on this model
            for m2m in self._meta.many_to_many:
                related_qs = getattr(self, m2m.name).all()
                getattr(new_instance, m2m.name).set(list(related_qs))

            # Finally delete the old instance (hard delete to remove row)
            try:
                self.hard_delete()
            except Exception:
                # If hard delete fails, try normal delete as fallback
                try:
                    super(self.__class__, self).delete()
                except Exception:
                    pass

        return new_instance

    class Meta:
        abstract = True


class SystemSettings(models.Model):
    """
    System-wide configuration settings
    Only one instance should exist - singleton pattern
    """

    # General Settings
    site_name = models.CharField(max_length=255, default="School Management System")
    site_url = models.URLField(default="http://localhost:3000")
    timezone = models.CharField(max_length=50, default="UTC")
    date_format = models.CharField(max_length=20, default="YYYY-MM-DD")
    time_format = models.CharField(max_length=10, default="24h")

    # Security Settings
    session_timeout = models.IntegerField(
        default=30, help_text="Session timeout in minutes"
    )
    max_login_attempts = models.IntegerField(default=5)
    password_min_length = models.IntegerField(default=8)
    require_2fa = models.BooleanField(
        default=False, help_text="Require two-factor authentication"
    )
    allow_user_registration = models.BooleanField(default=False)

    # Email Settings
    email_from_name = models.CharField(max_length=255, default="School Admin")
    email_from_address = models.EmailField(default="noreply@school.com")
    smtp_host = models.CharField(max_length=255, default="localhost")
    smtp_port = models.IntegerField(default=587)
    smtp_use_tls = models.BooleanField(default=True)

    # Notification Settings
    enable_email_notifications = models.BooleanField(default=True)
    enable_push_notifications = models.BooleanField(default=False)
    notification_retention_days = models.IntegerField(default=30)

    # System Settings
    maintenance_mode = models.BooleanField(default=False)
    debug_mode = models.BooleanField(default=False)
    log_level = models.CharField(
        max_length=20,
        default="INFO",
        choices=[
            ("DEBUG", "Debug"),
            ("INFO", "Info"),
            ("WARNING", "Warning"),
            ("ERROR", "Error"),
        ],
    )
    cache_enabled = models.BooleanField(default=True)

    # Metadata
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        "accounts.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="settings_updates",
    )

    class Meta:
        verbose_name = "System Settings"
        verbose_name_plural = "System Settings"

    def save(self, *args, **kwargs):
        """Ensure only one instance exists (singleton pattern)"""
        self.pk = 1
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Prevent deletion"""
        pass

    @classmethod
    def load(cls):
        """Load the singleton instance"""
        obj, created = cls.objects.get_or_create(pk=1)
        return obj

    def __str__(self):
        return f"System Settings - {self.site_name}"
