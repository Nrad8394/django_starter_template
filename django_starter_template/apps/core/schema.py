"""
Shared drf-spectacular building blocks.

Import these instead of retyping the same ``OpenApiParameter`` and
``OpenApiResponse`` definitions in every view. The point is that the generated
OpenAPI document describes what the API actually returns — including errors,
which is the half most specs get wrong.

The error schema here mirrors ``apps.core.exceptions`` exactly. If you change
the envelope there, change it here, or the spec lies and every generated
client is wrong in the same way.
"""

from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiExample, OpenApiParameter, OpenApiResponse

# ---------------------------------------------------------------------------
# The error envelope (see apps/core/exceptions.py)
# ---------------------------------------------------------------------------

ERROR_SCHEMA = {
    "type": "object",
    "required": ["error"],
    "properties": {
        "error": {
            "type": "object",
            "required": ["type", "message", "detail"],
            "properties": {
                "type": {
                    "type": "string",
                    "description": (
                        "Stable machine-readable slug. Branch on this, never "
                        "on `message`."
                    ),
                    "example": "validation_error",
                },
                "message": {
                    "type": "string",
                    "description": "One human-readable sentence, safe to display.",
                    "example": "Please correct the errors below.",
                },
                "detail": {
                    "type": "array",
                    "description": (
                        "Flat list of field errors. `field` uses dotted paths "
                        "for nested serializers (`items.1.qty`) and is null "
                        "for object-level errors."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": "string", "nullable": True},
                            "code": {"type": "string", "nullable": True},
                            "message": {"type": "string"},
                        },
                    },
                },
                "request_id": {
                    "type": "string",
                    "description": "Correlates this response with the server logs.",
                },
                "retry_after": {
                    "type": "integer",
                    "description": "Seconds to wait. Present on 429 only.",
                },
            },
        }
    },
}


def _error_response(description: str, example_type: str, example_message: str):
    return OpenApiResponse(
        description=description,
        response=ERROR_SCHEMA,
        examples=[
            OpenApiExample(
                "Error",
                value={
                    "error": {
                        "type": example_type,
                        "message": example_message,
                        "detail": [],
                        "request_id": "3f2a9c14-8b7d-4e21-9a5f-1c6e0b3d7a48",
                    }
                },
            )
        ],
    )


validation_error_response = OpenApiResponse(
    description="Validation failed",
    response=ERROR_SCHEMA,
    examples=[
        OpenApiExample(
            "Field errors",
            value={
                "error": {
                    "type": "validation_error",
                    "message": "Please correct the errors below.",
                    "detail": [
                        {
                            "field": "email",
                            "code": "required",
                            "message": "This field is required.",
                        },
                        {
                            "field": "items.1.quantity",
                            "code": "min_value",
                            "message": "Must be greater than zero.",
                        },
                    ],
                    "request_id": "3f2a9c14-8b7d-4e21-9a5f-1c6e0b3d7a48",
                }
            },
        )
    ],
)

#: Attach to any authenticated endpoint:
#:
#:     @extend_schema(responses={200: MySerializer, **common_responses})
common_responses = {
    400: validation_error_response,
    401: _error_response(
        "Not authenticated", "not_authenticated", "Authentication is required."
    ),
    403: _error_response(
        "Permission denied",
        "permission_denied",
        "You do not have permission to perform this action.",
    ),
    404: _error_response(
        "Not found", "not_found", "The requested resource was not found."
    ),
    429: _error_response(
        "Rate limited", "throttled", "Too many requests. Please slow down."
    ),
    500: _error_response(
        "Server error", "server_error", "An unexpected error occurred."
    ),
}

#: For public, unauthenticated endpoints — no 401/403 to document.
public_responses = {
    400: common_responses[400],
    404: common_responses[404],
    429: common_responses[429],
    500: common_responses[500],
}


# ---------------------------------------------------------------------------
# Reusable query parameters
# ---------------------------------------------------------------------------

pagination_parameters = [
    OpenApiParameter(
        name="page",
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description="1-based page number.",
    ),
    OpenApiParameter(
        name="page_size",
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description="Items per page, up to the view's maximum.",
    ),
]

filtering_parameters = [
    OpenApiParameter(
        name="search",
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description="Free-text search across the view's `search_fields`.",
    ),
    OpenApiParameter(
        name="ordering",
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description="Field to sort by. Prefix with `-` for descending.",
    ),
]

soft_delete_parameters = [
    OpenApiParameter(
        name="is_deleted",
        type=OpenApiTypes.BOOL,
        location=OpenApiParameter.QUERY,
        description=(
            "`false` (default) returns active records; `true` returns only "
            "soft-deleted ones — the trash view."
        ),
    ),
    OpenApiParameter(
        name="show_deleted",
        type=OpenApiTypes.BOOL,
        location=OpenApiParameter.QUERY,
        description="`true` returns active and deleted records together.",
    ),
]

#: Everything a standard list endpoint accepts.
list_parameters = pagination_parameters + filtering_parameters + soft_delete_parameters


# ---------------------------------------------------------------------------
# Async task responses
# ---------------------------------------------------------------------------

async_task_responses = {
    202: OpenApiResponse(
        description="Accepted — the work runs in the background",
        response={
            "type": "object",
            "properties": {
                "task_id": {"type": "string"},
                "status": {"type": "string", "example": "PENDING"},
            },
        },
    ),
    **common_responses,
}
