import uuid
from django.contrib.auth import get_user_model

User = get_user_model()


def UserFactory(**kwargs):
    """Simple factory for tests that creates a User with a unique email.

    This is intentionally minimal to avoid adding a factory_boy dependency.
    """
    email = kwargs.pop("email", None) or f"user-{uuid.uuid4().hex[:8]}@example.com"
    password = kwargs.pop("password", "password123")
    defaults = {"email": email}
    defaults.update(kwargs)
    # Use create_user to ensure proper password hashing and defaults
    return User.objects.create_user(password=password, **defaults)
