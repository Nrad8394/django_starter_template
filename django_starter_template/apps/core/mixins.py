"""
Optional model mixins.

Unlike ``apps.core.models``, nothing here is part of ``BaseModel``. Add these
to a model only when you want the behaviour.
"""

from __future__ import annotations

import secrets

from django.db import IntegrityError, models, transaction

# Crockford Base32: the digits and uppercase letters, minus I, L, O and U.
# I/1, L/1 and O/0 are the pairs people mistype when reading an ID off a
# screen or a printed invoice; U is excluded to reduce the chance of the
# alphabet spelling something unfortunate.
CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

DEFAULT_PUBLIC_ID_LENGTH = 10
MAX_GENERATION_ATTEMPTS = 5


def generate_public_id(prefix: str, length: int = DEFAULT_PUBLIC_ID_LENGTH) -> str:
    """Return ``{prefix}{random}``, e.g. ``INV8K2X7P9Q4Z``."""
    random_part = "".join(secrets.choice(CROCKFORD_ALPHABET) for _ in range(length))
    return f"{prefix}{random_part}"


class PublicIDMixin(models.Model):
    """
    Adds a short, human-readable identifier alongside the primary key.

    Why bother when the PK is already a UUID? Because a UUID is unusable in
    the physical world. Nobody reads ``f47ac10b-58cc-4372-a567-0e02b2c3d479``
    down a phone line, types it into a payment reference field, or prints it
    on an invoice. ``INV-8K2X7P9Q4Z`` survives all three.

    Keep both. The UUID stays the primary key and the foreign-key target;
    ``public_id`` is for humans and for external systems that need a stable
    short reference.

    Usage::

        class Invoice(PublicIDMixin, BaseModel):
            PUBLIC_ID_PREFIX = "INV"

    Collision math: with the 32-character alphabet and the default length of
    10, there are 32^10 ≈ 1.1e15 values. At a million rows the probability of
    any collision is on the order of 1e-3 — rare, and the unique constraint
    plus retry loop below handles it. Shorten the ID and that changes fast;
    at length 6 (1.07e9 values) a million rows collide with near certainty.
    Raise ``PUBLIC_ID_LENGTH`` before you shorten it.

    Not suitable as a secret. These IDs are guessable enough that anything
    reachable by ``public_id`` still needs a real authorization check —
    see ``apps/core/permissions.py``.
    """

    PUBLIC_ID_PREFIX: str = ""
    PUBLIC_ID_LENGTH: int = DEFAULT_PUBLIC_ID_LENGTH

    public_id = models.CharField(
        max_length=32,
        unique=True,
        db_index=True,
        editable=False,
        help_text="Short human-readable identifier.",
    )

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if self.public_id:
            return super().save(*args, **kwargs)

        # The database unique constraint is the source of truth, not a prior
        # exists() check — between the check and the insert another worker can
        # take the value. Retry on the IntegrityError instead.
        #
        # Each attempt gets its own savepoint. Without the nested atomic block
        # the failed INSERT would poison an enclosing transaction and every
        # subsequent statement would raise TransactionManagementError.
        last_error = None
        for _ in range(MAX_GENERATION_ATTEMPTS):
            self.public_id = generate_public_id(
                prefix=self.PUBLIC_ID_PREFIX,
                length=self.PUBLIC_ID_LENGTH,
            )
            try:
                with transaction.atomic():
                    return super().save(*args, **kwargs)
            except IntegrityError as exc:
                if "public_id" not in str(exc).lower():
                    # A different constraint failed — do not swallow it.
                    raise
                last_error = exc
                self.public_id = ""

        raise RuntimeError(
            f"Could not generate a unique public_id for "
            f"{self.__class__.__name__} after {MAX_GENERATION_ATTEMPTS} "
            f"attempts. The ID space is probably too small for the table "
            f"size — raise PUBLIC_ID_LENGTH."
        ) from last_error

    @classmethod
    def generate_unique_public_id(cls) -> str:
        """
        Produce a candidate ID without saving.

        Useful when you need a reference (a payment memo, say) before the
        object exists. Uses an ``exists()`` check, which is racy by nature —
        the write path above is the authoritative one.
        """
        for _ in range(MAX_GENERATION_ATTEMPTS):
            candidate = generate_public_id(
                prefix=cls.PUBLIC_ID_PREFIX,
                length=cls.PUBLIC_ID_LENGTH,
            )
            if not cls._default_manager.filter(public_id=candidate).exists():
                return candidate

        raise RuntimeError(
            f"Could not generate a unique public_id for {cls.__name__}."
        )

    @property
    def display_id(self) -> str:
        """``INV8K2X7P9Q4Z`` rendered as ``INV-8K2X7P9Q4Z``."""
        prefix_length = len(self.PUBLIC_ID_PREFIX)
        if not prefix_length or len(self.public_id) <= prefix_length:
            return self.public_id
        return f"{self.public_id[:prefix_length]}-{self.public_id[prefix_length:]}"
