"""
Abstract base models shared by every app in the project.

What lives here
---------------
``TimestampedModel``  UUID primary key + created/updated timestamps.
``AuditMixin``        created_by / updated_by foreign keys.
``SoftDeleteMixin``   is_deleted / deleted_at / deleted_by + managers.
``BaseModel``         all three combined — the default base for entities.
``SingletonModel``    single-row configuration tables, cached.

Design notes are inline. The short version of the two decisions most likely to
bite you:

1. Soft delete really deletes nothing, so ``objects`` must filter and
   ``_base_manager`` must not. See ``SoftDeleteMixin``.
2. Audit foreign keys point at ``settings.AUTH_USER_MODEL``, never at a
   hard-coded app label — the whole point of a template is that the user model
   is the app's to choose.
"""

import uuid

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

# ---------------------------------------------------------------------------
# Managers & querysets
# ---------------------------------------------------------------------------


class SoftDeleteQuerySet(models.QuerySet):
    """
    QuerySet that understands soft deletion.

    ``delete()`` is overridden so that bulk operations (``qs.delete()``) do not
    quietly bypass the soft-delete contract that ``instance.delete()`` honours.
    It returns the same ``(total, {label: count})`` tuple Django's own
    ``delete()`` returns so calling code does not need to special-case it.
    """

    def delete(self, deleted_by=None):
        updates = {
            "is_deleted": True,
            "deleted_at": timezone.now(),
        }
        # Not every model using this queryset necessarily carries deleted_by.
        field_names = {field.name for field in self.model._meta.get_fields()}
        if "deleted_by" in field_names:
            updates["deleted_by"] = deleted_by

        count = super().update(**updates)
        return count, {self.model._meta.label: count}

    def hard_delete(self):
        """Really remove the rows. Bypasses the soft-delete contract."""
        return super().delete()

    def alive(self):
        """Only rows that have not been soft-deleted."""
        return self.filter(is_deleted=False)

    def dead(self):
        """Only rows that have been soft-deleted."""
        return self.filter(is_deleted=True)

    def restore(self):
        """Bulk-undo a soft delete."""
        return super().update(is_deleted=False, deleted_at=None, deleted_by=None)


class SoftDeleteManager(models.Manager.from_queryset(SoftDeleteQuerySet)):
    """Default manager: hides soft-deleted rows."""

    def get_queryset(self):
        return super().get_queryset().alive()


class AllObjectsManager(models.Manager.from_queryset(SoftDeleteQuerySet)):
    """
    Escape hatch manager: returns every row, deleted or not.

    Built ``from_queryset`` so ``Model.all_objects.dead()`` works. A plain
    ``models.Manager()`` here would return a bare QuerySet and none of the
    soft-delete helpers would be available — an easy detail to get wrong.
    """


class SingletonManager(models.Manager):
    """Refuses bulk deletion of a single-row table."""

    def delete(self):  # pragma: no cover - defensive
        raise ValidationError("Singleton instances cannot be deleted.")


# ---------------------------------------------------------------------------
# Abstract base classes
# ---------------------------------------------------------------------------


class TimestampedModel(models.Model):
    """
    UUID primary key plus creation/modification timestamps.

    Why UUIDs rather than auto-incrementing integers: sequential IDs leak
    business volume ("we are customer #42") and make enumeration attacks
    trivial on any endpoint whose object-level permission check is imperfect.
    The cost is a wider index and non-monotonic inserts.

    If you would rather have the integer PK back — because you have a
    high-write table where B-tree fragmentation matters, or you need ordered
    IDs — drop the ``id`` field from a subclass and Django restores the default
    ``AutoField``. Consider UUIDv7 (time-ordered) as a middle ground.

    ``created_at`` is indexed because ``ordering`` below sorts on it, so
    essentially every list query touches it.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]


class AuditMixin(models.Model):
    """
    Tracks who created and last modified a row.

    ``on_delete=SET_NULL`` rather than ``CASCADE``: deleting a user account
    must not delete the business records that user happened to touch.

    Populating these fields is the caller's job. The template wires it up in
    ``apps.core.viewsets.BaseModelViewSet.perform_create`` /
    ``perform_update``. The alternative — a thread-local "current user"
    middleware — is deliberately not the default here; see ``PATTERNS.md``
    for why.
    """

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_created",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_updated",
    )

    class Meta:
        abstract = True


class SoftDeleteMixin(models.Model):
    """
    Marks rows deleted instead of removing them.

    Three things have to line up for this to actually work, and it is common
    to get one of them wrong:

    1. ``delete()`` must be overridden on the *instance*, or
       ``obj.delete()`` hard-deletes.
    2. ``objects`` must filter deleted rows out, or every list view leaks
       them.
    3. ``Meta.base_manager_name`` must point at a manager that does *not*
       filter, or Django's related-object descriptors break. Accessing
       ``some_invoice.customer`` where the customer is soft-deleted would
       raise ``DoesNotExist``, and cascade collection during a real delete
       would silently miss rows. Django uses ``_base_manager`` for exactly
       these internal traversals and documents that it must not filter.

    Subclasses inherit all three. ``Meta.base_manager_name`` is set on this
    abstract class, so a subclass that declares its own ``Meta`` should
    inherit from ``SoftDeleteMixin.Meta`` (or re-declare the attribute).

    Cost to be aware of: unique constraints still see soft-deleted rows. If a
    user "deletes" an account with email ``a@b.com`` they cannot re-register
    with it. Use a partial unique index for those columns::

        class Meta(SoftDeleteMixin.Meta):
            constraints = [
                models.UniqueConstraint(
                    fields=["email"],
                    condition=models.Q(is_deleted=False),
                    name="unique_active_email",
                ),
            ]
    """

    is_deleted = models.BooleanField(default=False, db_index=True)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="%(app_label)s_%(class)s_deleted",
    )

    objects = SoftDeleteManager()
    all_objects = AllObjectsManager()

    class Meta:
        abstract = True
        base_manager_name = "all_objects"

    def delete(self, deleted_by=None, using=None, keep_parents=False):
        """Soft delete. Pass ``deleted_by`` to record who did it."""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = deleted_by
        self.save(
            using=using,
            update_fields=["is_deleted", "deleted_at", "deleted_by"],
        )

    def restore(self):
        """Undo a soft delete."""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save(update_fields=["is_deleted", "deleted_at", "deleted_by"])

    def hard_delete(self, using=None, keep_parents=False):
        """Really remove the row, cascading as Django normally would."""
        return super().delete(using=using, keep_parents=keep_parents)


class BaseModel(TimestampedModel, AuditMixin, SoftDeleteMixin):
    """
    The default base class for domain entities.

    UUID PK + timestamps + audit fields + soft delete.

    Not every model wants all of this. A high-volume append-only log table
    probably wants ``TimestampedModel`` alone; a join table probably wants
    plain ``models.Model``. Inheriting ``BaseModel`` everywhere costs five
    columns and two indexes per table.
    """

    class Meta:
        abstract = True
        base_manager_name = "all_objects"
        ordering = ["-created_at"]


class SingletonModel(models.Model):
    """
    Base class for single-row configuration tables.

    Reads go through the cache, so ``MyConfig.load()`` in a hot code path does
    not hit the database on every request. ``save()`` refreshes the cache
    entry, so a value written through the admin is visible immediately.

    Caveat for multi-process deployments: each worker holds its own cache
    entry unless you use a shared backend (Redis/Memcached). With the
    local-memory cache, a change saved by worker A is invisible to worker B
    until B restarts. Use a shared cache backend if that matters.

    Usage::

        class BrandingSettings(SingletonModel):
            CACHE_KEY = "branding_settings"
            support_email = models.EmailField(default="")

        BrandingSettings.load().support_email
    """

    CACHE_KEY = None

    objects = SingletonManager()

    class Meta:
        abstract = True

    def clean(self):
        if not self.pk and self.__class__.objects.exists():
            raise ValidationError(
                f"Only one instance of {self.__class__.__name__} is allowed."
            )

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)
        cache.set(self.get_cache_key(), self, timeout=None)

    def delete(self, *args, **kwargs):
        raise ValidationError("Singleton instances cannot be deleted.")

    @classmethod
    def get_cache_key(cls):
        return cls.CACHE_KEY or f"singleton:{cls._meta.label_lower}"

    @classmethod
    def load(cls):
        """Return the single instance, creating it on first access."""
        return cache.get_or_set(
            cls.get_cache_key(),
            lambda: cls.objects.get_or_create(pk=1)[0],
            timeout=None,
        )

    @classmethod
    def invalidate_cache(cls):
        cache.delete(cls.get_cache_key())
