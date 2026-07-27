"""
Pagination classes.

The response shape adds ``page_size``, ``total_pages`` and ``current_page`` to
DRF's default ``count/next/previous/results``. Those three are what a table UI
needs to render a page-number control; without them the client has to derive
them from ``count`` and its own page-size assumption, which drifts the moment
anyone passes ``?page_size=``.

The frontend template's ``DjangoPaginatedResponse<T>`` type mirrors this
exactly — change one, change the other.
"""

from collections import OrderedDict

from rest_framework.pagination import CursorPagination, PageNumberPagination
from rest_framework.response import Response


class BasePageNumberPagination(PageNumberPagination):
    """
    Shared response shape. Subclass to change the page size, nothing else.

    (The original version of this file repeated an identical
    ``get_paginated_response`` in three classes. Three copies of a method that
    must stay byte-identical to keep the API contract stable is three chances
    to break it.)
    """

    page_size_query_param = "page_size"

    def get_paginated_response(self, data):
        return Response(
            OrderedDict(
                [
                    ("count", self.page.paginator.count),
                    ("next", self.get_next_link()),
                    ("previous", self.get_previous_link()),
                    ("page_size", self.get_page_size(self.request)),
                    ("total_pages", self.page.paginator.num_pages),
                    ("current_page", self.page.number),
                    ("results", data),
                ]
            )
        )

    def get_paginated_response_schema(self, schema):
        """Keep the generated OpenAPI spec honest about the extra keys."""
        return {
            "type": "object",
            "required": ["count", "results"],
            "properties": {
                "count": {"type": "integer", "example": 123},
                "next": {"type": "string", "nullable": True, "format": "uri"},
                "previous": {"type": "string", "nullable": True, "format": "uri"},
                "page_size": {"type": "integer", "example": self.page_size},
                "total_pages": {"type": "integer", "example": 7},
                "current_page": {"type": "integer", "example": 1},
                "results": schema,
            },
        }


class StandardResultsSetPagination(BasePageNumberPagination):
    """Project default. Set as ``DEFAULT_PAGINATION_CLASS``."""

    page_size = 20
    max_page_size = 100


class SmallResultsSetPagination(BasePageNumberPagination):
    """For expensive serializers, or mobile clients on a metered connection."""

    page_size = 10
    max_page_size = 50


class LargeResultsSetPagination(BasePageNumberPagination):
    """For cheap, flat rows — dropdown options, lookup tables."""

    page_size = 50
    max_page_size = 200


class StandardCursorPagination(CursorPagination):
    """
    Use this instead of page numbers on large, frequently-written tables.

    Two reasons page numbers go wrong at scale:

    * ``OFFSET 100000`` makes the database walk and discard 100,000 rows.
      Cursor pagination is a ``WHERE created_at < ?`` — an index seek,
      constant cost at any depth.
    * With rows being inserted while a user pages, offset pagination shows
      duplicates and skips records. A cursor is anchored to a row, so it
      does not drift.

    The trade-off is real: no jump-to-page-N, and no total count (computing
    one would reintroduce the full scan). Only adopt it where the UI is an
    infinite-scroll list rather than a numbered table.

    ``ordering`` must match a field with a database index, and should be
    unique or near-unique — ties at the cursor boundary can be skipped.
    """

    page_size = 20
    max_page_size = 100
    page_size_query_param = "page_size"
    ordering = "-created_at"
