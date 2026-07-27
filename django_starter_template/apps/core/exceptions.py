"""
A single, stable error envelope for every API response.

The problem this solves
-----------------------
DRF's default exception handler returns whatever shape the exception happens
to carry:

    ValidationError   ->  {"email": ["This field is required."]}
    ValidationError   ->  {"non_field_errors": ["Passwords do not match."]}
    PermissionDenied  ->  {"detail": "You do not have permission..."}
    Http404           ->  {"detail": "Not found."}
    IntegrityError    ->  an HTML 500 page
    nested serializer ->  {"items": [{}, {"qty": ["Must be positive."]}]}

Six shapes, and the client has to guess which one it got. What happens next is
predictable and was observed in a real project built from this template: the
frontend grew a 150-line error handler that walks unknown object graphs,
special-cases each status code, and — because DRF's ``ErrorDetail`` is a
``str`` subclass whose ``repr()`` leaks through some serialization paths —
ends up doing this:

    const pattern = /ErrorDetail\\(string='([^']+)',\\s*code='([^']+)'\\)/g

Regex-parsing a Python ``repr()`` in TypeScript is the symptom. The cause is
that the API never committed to a response contract. Fixing it on the client
is fixing it in the wrong place, and every new client (mobile app, CLI,
partner integration) pays the cost again.

The envelope
------------
Every non-2xx response from the API looks like this, always::

    {
      "error": {
        "type":    "validation_error",
        "message": "Please correct the errors below.",
        "detail":  [
          {"field": "email", "code": "required", "message": "This field is required."},
          {"field": "items.1.qty", "code": "min_value", "message": "Must be positive."}
        ],
        "request_id": "0f9c3a1e-..."
      }
    }

  ``type``       stable machine-readable slug; branch on this, not on prose.
  ``message``    one human-readable sentence, safe to show in a toast.
  ``detail``     flat list of per-field errors. Nested serializer paths are
                 flattened with dots, so the client can map straight onto a
                 form field name without walking a tree.
  ``request_id`` correlates the user's screenshot with your logs.

The client-side consequence is that the entire error handler collapses to:
read ``error.message`` for the toast, iterate ``error.detail`` to mark fields.
No shape sniffing, no regex. See the matching
``lib/api/errors.ts`` in the frontend template.

Trade-offs
----------
  * Non-standard. If you would rather adopt RFC 9457 (``application/
    problem+json``) the mapping is mechanical: ``type`` -> a URI,
    ``message`` -> ``title``, ``detail`` stays. This template uses a plain
    JSON envelope because RFC 9457's URI-valued ``type`` field is rarely
    dereferenced in practice and adds ceremony without adding information.
  * It breaks DRF's browsable-API error rendering slightly, and any
    third-party DRF package whose tests assert on ``response.data["detail"]``
    will need updating. ``ERROR_ENVELOPE_EXEMPT_PATH_PREFIXES`` below is the
    escape hatch for those.

Wire-up (already done in ``settingsConfig/api/rest.py``)::

    REST_FRAMEWORK = {
        "EXCEPTION_HANDLER": "apps.core.exceptions.api_exception_handler",
    }
"""

from __future__ import annotations

import logging
import uuid

from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError
from django.db.models.deletion import ProtectedError, RestrictedError
from django.http import Http404
from rest_framework import exceptions as drf_exceptions
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_exception_handler

logger = logging.getLogger(__name__)

#: Requests whose path starts with one of these keep DRF's native error shape.
#: Useful for third-party mounted apps that assert on the default format.
ERROR_ENVELOPE_EXEMPT_PATH_PREFIXES: tuple[str, ...] = ()

#: Maps a DRF exception class to the ``type`` slug clients branch on.
#: Slugs are part of your public API contract — renaming one is a breaking
#: change, so pick them deliberately.
EXCEPTION_TYPE_MAP = {
    drf_exceptions.ParseError: "parse_error",
    drf_exceptions.AuthenticationFailed: "authentication_failed",
    drf_exceptions.NotAuthenticated: "not_authenticated",
    drf_exceptions.PermissionDenied: "permission_denied",
    drf_exceptions.NotFound: "not_found",
    drf_exceptions.MethodNotAllowed: "method_not_allowed",
    drf_exceptions.NotAcceptable: "not_acceptable",
    drf_exceptions.UnsupportedMediaType: "unsupported_media_type",
    drf_exceptions.Throttled: "throttled",
    drf_exceptions.ValidationError: "validation_error",
}

#: Fallback ``message`` per status code, used when the exception carries no
#: usable prose of its own.
DEFAULT_MESSAGES = {
    400: "The request could not be processed.",
    401: "Authentication is required.",
    403: "You do not have permission to perform this action.",
    404: "The requested resource was not found.",
    405: "That method is not allowed on this endpoint.",
    409: "The request conflicts with the current state of the resource.",
    415: "Unsupported media type.",
    429: "Too many requests. Please slow down.",
    500: "An unexpected error occurred.",
}

#: DRF puts errors that belong to the object as a whole (rather than to one
#: field) under this key. The envelope reports them with ``field: null``.
NON_FIELD_KEY = "non_field_errors"


def _error_type_for(exc, status_code: int) -> str:
    for exc_class, slug in EXCEPTION_TYPE_MAP.items():
        if isinstance(exc, exc_class):
            return slug
    if status_code >= 500:
        return "server_error"
    return "error"


def _flatten(detail, path: str = "") -> list[dict]:
    """
    Turn DRF's arbitrarily nested error structure into a flat list.

    DRF nests errors to mirror the serializer tree::

        {"items": [{}, {"qty": [ErrorDetail("Must be positive.", "min_value")]}]}

    The client does not want that tree; it wants to mark one input. So each
    leaf becomes ``{"field": "items.1.qty", "code": ..., "message": ...}`` —
    a dotted path that maps directly onto the form library's field name.

    ``ErrorDetail`` is a ``str`` subclass carrying a ``.code``; ``str()`` on it
    yields the message and never the ``repr()``. Doing that conversion *here*,
    once, is what stops the ``repr()`` from ever reaching the wire.
    """
    items: list[dict] = []

    if isinstance(detail, dict):
        for key, value in detail.items():
            if key == NON_FIELD_KEY:
                child_path = path
            else:
                child_path = f"{path}.{key}" if path else str(key)
            items.extend(_flatten(value, child_path))
        return items

    if isinstance(detail, (list, tuple)):
        # A list of dicts is a nested many=True serializer: the index is part
        # of the field path. A list of plain messages is just several errors
        # on the same field, so the index is noise and gets dropped.
        indexed = any(isinstance(entry, (dict, list, tuple)) for entry in detail)
        for index, entry in enumerate(detail):
            child_path = f"{path}.{index}" if (indexed and path) else path
            items.extend(_flatten(entry, child_path))
        return items

    items.append(
        {
            "field": path or None,
            "code": getattr(detail, "code", None),
            "message": str(detail),
        }
    )
    return items


def _summary_message(errors: list[dict], status_code: int) -> str:
    """
    Pick the single sentence a client can show without any further logic.

    Preference order: an object-level error (no field) reads as a complete
    sentence and wins; otherwise, if there is exactly one field error, show
    it; otherwise fall back to a generic line and let the client render the
    per-field list against the form.
    """
    object_level = [e for e in errors if not e["field"]]
    if object_level:
        return object_level[0]["message"]

    if len(errors) == 1 and errors[0]["message"]:
        return errors[0]["message"]

    if errors:
        return "Please correct the errors below."

    return DEFAULT_MESSAGES.get(status_code, DEFAULT_MESSAGES[500])


def _build_envelope(*, error_type, message, errors, request_id, extra=None):
    payload = {
        "type": error_type,
        "message": message,
        "detail": errors,
        "request_id": request_id,
    }
    if extra:
        payload.update(extra)
    return {"error": payload}


def _translate_django_exception(exc):
    """
    Convert the Django-level exceptions DRF does not handle into DRF ones.

    Without this, an ``IntegrityError`` from a race on a unique constraint —
    a completely routine event — becomes a 500 and an alert page. It is a
    client error: the row already exists.
    """
    if isinstance(exc, Http404):
        return drf_exceptions.NotFound()

    if isinstance(exc, DjangoPermissionDenied):
        return drf_exceptions.PermissionDenied()

    if isinstance(exc, DjangoValidationError):
        # Django's ValidationError exposes either message_dict (field errors)
        # or messages (object-level). DRF's expects the former shape.
        detail = getattr(exc, "message_dict", None) or {
            NON_FIELD_KEY: list(exc.messages)
        }
        return drf_exceptions.ValidationError(detail)

    if isinstance(exc, (ProtectedError, RestrictedError)):
        return drf_exceptions.ValidationError(
            {
                NON_FIELD_KEY: [
                    "This record is referenced by other records and cannot "
                    "be deleted."
                ]
            }
        )

    if isinstance(exc, IntegrityError):
        return drf_exceptions.ValidationError(
            {NON_FIELD_KEY: ["That change conflicts with an existing record."]}
        )

    return None


def api_exception_handler(exc, context):
    """
    DRF ``EXCEPTION_HANDLER``.

    Returns the envelope described in this module's docstring for every
    handled exception, and ``None`` for genuinely unexpected ones so Django's
    own 500 machinery (and your error tracker) still sees them — with one
    exception: when ``DEBUG`` is off we convert them to a 500 envelope too,
    because an HTML error page is useless to an API client.
    """
    request = context.get("request")
    request_id = str(
        getattr(request, "id", None)
        or (request and request.META.get("HTTP_X_REQUEST_ID"))
        or uuid.uuid4()
    )

    path = getattr(request, "path", "") or ""
    if path.startswith(ERROR_ENVELOPE_EXEMPT_PATH_PREFIXES or ()):
        return drf_exception_handler(exc, context)

    translated = _translate_django_exception(exc)
    if translated is not None:
        exc = translated

    response = drf_exception_handler(exc, context)

    if response is None:
        # Not a DRF exception: a real, unexpected server error.
        logger.exception(
            "Unhandled exception in %s [request_id=%s]",
            path or "<no request>",
            request_id,
            extra={"request_id": request_id},
        )

        if settings.DEBUG:
            # Let Django's debug page render — far more useful locally than
            # a JSON blob with no traceback.
            return None

        return Response(
            _build_envelope(
                error_type="server_error",
                message=DEFAULT_MESSAGES[500],
                errors=[],
                request_id=request_id,
            ),
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    errors = _flatten(response.data)
    error_type = _error_type_for(exc, response.status_code)
    message = _summary_message(errors, response.status_code)

    extra = {}
    if isinstance(exc, drf_exceptions.Throttled) and exc.wait is not None:
        # Give the client something it can act on rather than a bare 429.
        extra["retry_after"] = int(exc.wait)

    response.data = _build_envelope(
        error_type=error_type,
        message=message,
        errors=errors,
        request_id=request_id,
        extra=extra or None,
    )

    if response.status_code >= 500:
        logger.error(
            "API error %s in %s [request_id=%s]: %s",
            response.status_code,
            path,
            request_id,
            message,
            extra={"request_id": request_id},
        )

    return response
