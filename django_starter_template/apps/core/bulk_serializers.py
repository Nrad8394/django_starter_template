"""
Request serializers for the bulk endpoints on ``BaseModelViewSet``.

These live apart from ``apps/core/serializers.py`` on purpose. That module
imports allauth and dj-rest-auth to customise the auth flows; importing it
from ``viewsets.py`` would mean every viewset in the project transitively
depends on the authentication stack, and a project that swaps allauth out
could no longer import its own base viewset. This module imports nothing but
DRF.

Their second job is documentation. Because the bulk actions declare
``request=`` with these classes, drf-spectacular emits a real request schema
for each one instead of an untyped blob, so the generated client and the API
docs both know the shape.
"""

from rest_framework import serializers


class FileUploadSerializer(serializers.Serializer):
    """A single uploaded file. Used by import endpoints."""

    file = serializers.FileField(
        help_text="CSV or XLSX file. The first row must be the column headers."
    )


class BulkIdListSerializer(serializers.Serializer):
    """
    ``{"ids": [...]}`` for bulk delete and restore.

    ``allow_empty=False`` turns "the client sent an empty list" into a 400
    with a clear message rather than a cheerful ``{"count": 0}`` that looks
    like the operation ran. Silent no-ops are hard to debug from the UI side.

    The ids are ``CharField`` rather than ``UUIDField`` so the template works
    unchanged if you swap ``BaseModel``'s UUID primary key for an integer.
    The queryset filter that consumes them coerces and validates per the
    model's actual field type.
    """

    ids = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False,
        help_text="Primary keys of the objects to act on.",
    )


class BulkUpdateEntrySerializer(serializers.Serializer):
    """One ``{"id": ..., "data": {...}}`` pair."""

    id = serializers.CharField(help_text="Primary key of the object to update.")
    data = serializers.DictField(
        allow_empty=False,
        help_text="Fields to change. Validated by the resource serializer.",
    )


class BulkUpdateSerializer(serializers.Serializer):
    """
    ``{"updates": [{"id": ..., "data": {...}}, ...]}``.

    Note what this shape does *not* allow: a single ``data`` object applied to
    a list of ids. That form is tempting — it maps neatly onto
    ``QuerySet.update()`` and is one SQL statement — but ``QuerySet.update()``
    skips serializer validation, model ``save()``, signals, and ``auto_now``,
    and places no limit on which columns the caller may name. It is a
    mass-assignment vulnerability wearing a convenience API's clothes.

    If you need genuine bulk-set performance for a specific case, write a
    narrow endpoint that names the one field it changes and validates the
    value — for example ``POST /orders/mark_shipped/`` taking only ``ids``.
    """

    updates = serializers.ListField(
        child=BulkUpdateEntrySerializer(),
        allow_empty=False,
        help_text="One entry per object to update.",
    )

    def validate_updates(self, value):
        seen = set()
        duplicates = set()
        for entry in value:
            key = str(entry["id"])
            if key in seen:
                duplicates.add(key)
            seen.add(key)

        if duplicates:
            # Two updates to the same row in one request have an
            # order-dependent outcome. Reject rather than pick a winner.
            raise serializers.ValidationError(
                f"Duplicate id(s) in the request: {', '.join(sorted(duplicates))}."
            )
        return value


class BulkResultSerializer(serializers.Serializer):
    """Response shape shared by the bulk write endpoints. Documentation only."""

    count = serializers.IntegerField(help_text="Objects successfully affected.")
    message = serializers.CharField(required=False)
    blocked = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Objects a business rule refused, with the reason.",
    )
