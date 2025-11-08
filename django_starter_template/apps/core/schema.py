from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse,
    OpenApiTypes,
)
from drf_spectacular.types import OpenApiTypes
from django.urls import re_path, path
from rest_framework import viewsets

common_responses = {
    400: OpenApiResponse(
        description="Bad request - invalid input",
        examples=[{
            'type': 'validation_error',
            'errors': {
                'field': ['Error message']
            }
        }]
    ),
    401: OpenApiResponse(
        description="Authentication required",
        examples=[{
            'detail': 'Authentication credentials were not provided.'
        }]
    ),
    403: OpenApiResponse(
        description="Permission denied",
        examples=[{
            'detail': 'You do not have permission to perform this action.'
        }]
    ),
    404: OpenApiResponse(
        description="Resource not found",
        examples=[{
            'detail': 'Not found.'
        }]
    ),
    500: OpenApiResponse(
        description="Server error",
        examples=[{
            'detail': 'A server error occurred.'
        }]
    )
}

pagination_parameters = [
    OpenApiParameter(
        name='page',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Page number',
        required=False,
    ),
    OpenApiParameter(
        name='page_size',
        type=OpenApiTypes.INT,
        location=OpenApiParameter.QUERY,
        description='Number of items per page',
        required=False,
    ),
]

workflow_responses = {
    **common_responses,
    422: OpenApiResponse(
        description="Invalid workflow transition",
        examples=[{
            'detail': 'Invalid status transition.'
        }]
    )
}

async_task_responses = {
    **common_responses,
    202: OpenApiResponse(
        description="Task accepted",
        examples=[{
            'task_id': 'uuid',
            'status': 'PENDING'
        }]
    )
}

file_upload_parameters = [
    OpenApiParameter(
        name='file',
        type=OpenApiTypes.BINARY,
        location='form',
        description='File to upload',
        required=True,
    )
]

filtering_parameters = [
    OpenApiParameter(
        name='search',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Search term',
        required=False,
    ),
    OpenApiParameter(
        name='ordering',
        type=OpenApiTypes.STR,
        location=OpenApiParameter.QUERY,
        description='Ordering field (prefix with - for descending)',
        required=False,
    ),
]