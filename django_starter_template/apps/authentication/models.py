from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from apps.core.models import  BaseModel
from django.contrib.auth.models import AbstractUser, BaseUserManager, Permission

# Create your models here.
class UserRole(BaseModel):
    """
    User roles for role-based access control
    """

    name = models.CharField(
        max_length=100, unique=True, help_text=_("Unique role identifier")
    )
    display_name = models.CharField(
        max_length=100, help_text=_("Human-readable role name"), unique=True
    )
    description = models.TextField(blank=True, help_text=_("Role description"))
    is_active = models.BooleanField(
        default=True, help_text=_("Whether this role is active")
    )
    permissions = models.ManyToManyField(
        Permission,
        blank=True,
        related_name="user_roles",
        help_text=_("Permissions assigned to this role"),
    )

    class Meta:
        app_label = "authentication"
        verbose_name = "User Role"
        verbose_name_plural = "User Roles"
        ordering = ["display_name"]
        indexes = [
            models.Index(fields=["is_active","updated_at"]),
            models.Index(fields=["-created_at"]),
            models.Index(fields=["-updated_at"]),
        ]

    def __str__(self):
        return self.display_name

    def clean(self):
        """Validate role data"""
        if not self.name:
            raise ValidationError(_("Role name is required"))
        if not self.display_name:
            raise ValidationError(_("Display name is required"))


class UserManager(BaseUserManager):
    """Custom manager for User model with email as username field"""

    def create_user(self, email, password=None, **extra_fields):
        """Create and save a User with the given email and password."""
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser, BaseModel):
    """
    Custom user model with email authentication and role-based access
    """

    objects = UserManager()
    # Override base UUID id to use institution-friendly user ID as primary key.
    # The DB column will be named `user_id` for clarity while the model's PK is `id`.
    id = models.CharField(
        primary_key=True,
        max_length=50,
        editable=True,
        unique=True,
        db_column='user_id',
        help_text=_("Institutional user ID used as primary key, e.g. SIG00125"),
    )
    # Role-based access control
    role = models.ForeignKey(
        UserRole,
        on_delete=models.PROTECT,  # Prevent deletion of role if users exist
        null=False,  # Role is REQUIRED
        blank=False,  # Must be provided
        related_name="users",
        help_text=_("User's role for permissions - REQUIRED"),
    )
    # Override required fields
    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS = ["first_name", "last_name"]

    class Meta:
        app_label = "authentication"
        verbose_name = "Auth User"
        verbose_name_plural = "Auth Users"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["is_active", "-created_at"]),
            models.Index(fields=["is_active", "-updated_at"]),
        ]

    def __str__(self):
        return f"{self.full_name} ({self.email})"

    @property
    def full_name(self):
        """Return the full name of the user."""
        return f"{self.first_name} {self.last_name}".strip()