"""
Project middleware.

Ordering matters and is documented in
``settingsConfig/core/middleware.py``. The rule of thumb: anything that
annotates the request (tracing) goes near the top so everything downstream can
read it; anything that measures or catches (timing, error handling) wraps the
rest and so goes near the top as well, since middleware nests.
"""

import logging
import time
import uuid

from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

#: Header a load balancer or upstream gateway may already have set. Reusing an
#: inbound id is what makes a trace span services instead of restarting at
#: each hop.
REQUEST_ID_HEADER = "HTTP_X_REQUEST_ID"
REQUEST_ID_RESPONSE_HEADER = "X-Request-ID"


class RequestIDMiddleware(MiddlewareMixin):
    """
    Give every request a stable id and echo it back to the client.

    Sets ``request.id``, which:

      * ``apps.core.exceptions`` puts in the error envelope, so a user can
        paste an id from a screenshot and you can find the exact request;
      * ``settingsConfig/logging`` attaches to every log record via
        ``RequestIDFilter``, so all log lines for one request share a key.

    Trusting an inbound ``X-Request-ID`` is the right default behind your own
    gateway and the wrong default on a public edge — a client can send a
    duplicate or an oversized value and pollute your logs. The length cap and
    character filter below make abuse harmless; set
    ``TRUST_INBOUND_REQUEST_ID = False`` to ignore the header entirely.
    """

    TRUST_INBOUND_REQUEST_ID = True
    MAX_REQUEST_ID_LENGTH = 64

    def process_request(self, request):
        request_id = None

        if self.TRUST_INBOUND_REQUEST_ID:
            inbound = request.META.get(REQUEST_ID_HEADER, "")
            candidate = "".join(
                c for c in inbound if c.isalnum() or c in "-_."
            )[: self.MAX_REQUEST_ID_LENGTH]
            request_id = candidate or None

        request.id = request_id or str(uuid.uuid4())

    def process_response(self, request, response):
        request_id = getattr(request, "id", None)
        if request_id:
            response[REQUEST_ID_RESPONSE_HEADER] = request_id
        return response


class RequestTimingMiddleware(MiddlewareMixin):
    """
    Log requests slower than a threshold and expose the timing as a header.

    The threshold is a setting rather than a constant so it can be tightened
    per environment — a 2-second bar that never fires teaches you nothing.

    This measures Django's own time only: it starts after the web server has
    parsed the request and stops before the response is written to the socket.
    Do not use these numbers as your user-facing latency SLI; use the
    reverse proxy's access log or real user monitoring for that.
    """

    @property
    def threshold(self):
        return getattr(settings, "SLOW_REQUEST_THRESHOLD_SECONDS", 1.0)

    def process_request(self, request):
        request.start_time = time.perf_counter()

    def process_response(self, request, response):
        start = getattr(request, "start_time", None)
        if start is None:
            return response

        duration = time.perf_counter() - start
        response["X-Response-Time-Ms"] = f"{duration * 1000:.1f}"

        if duration > self.threshold:
            logger.warning(
                "Slow request: %s %s took %.3fs",
                request.method,
                request.path,
                duration,
                extra={
                    "request_id": getattr(request, "id", None),
                    "path": request.path,
                    "method": request.method,
                    "duration_seconds": round(duration, 4),
                    "status_code": response.status_code,
                },
            )

        return response


class APIErrorEnvelopeMiddleware(MiddlewareMixin):
    """
    Catch exceptions raised *outside* DRF and return the same error envelope.

    ``apps.core.exceptions.api_exception_handler`` covers everything that
    happens inside a DRF view. It cannot cover what happens before the view is
    reached — a broken middleware, a failure in URL resolution, an exception
    in authentication. Those produce Django's HTML 500 page, which an API
    client cannot parse.

    Without this, a project ends up with two error contracts: a clean JSON
    envelope most of the time and an HTML page in exactly the situations where
    a client most needs a machine-readable answer. The shape below is
    byte-identical to the DRF handler's, so a client parses one thing.

    Kept out of the loop in ``DEBUG``: Django's traceback page is far more
    useful locally than a JSON blob.
    """

    #: Paths that should keep Django's normal HTML error handling.
    HTML_PATH_PREFIXES = ("/admin/",)

    def process_exception(self, request, exception):
        request_id = getattr(request, "id", None) or str(uuid.uuid4())

        logger.exception(
            "Unhandled exception: %s %s",
            request.method,
            request.path,
            extra={
                "request_id": request_id,
                "path": request.path,
                "method": request.method,
            },
        )

        if settings.DEBUG:
            return None

        if request.path.startswith(self.HTML_PATH_PREFIXES):
            return None

        api_prefix = getattr(settings, "API_PATH_PREFIX", "/api/")
        if not request.path.startswith(api_prefix):
            return None

        return JsonResponse(
            {
                "error": {
                    "type": "server_error",
                    "message": "An unexpected error occurred.",
                    "detail": [],
                    "request_id": request_id,
                }
            },
            status=500,
        )


class CurrentUserMiddleware(MiddlewareMixin):
    """
    Store the request's user in a thread-local for model-layer access.

    DISABLED BY DEFAULT, and worth understanding before you enable it.

    It exists to let ``Model.save()`` populate ``created_by``/``updated_by``
    without every caller passing a user. That convenience is real, and so are
    the costs:

      * **It lies outside a request.** Celery tasks, management commands and
        data migrations have no request, so the thread-local is empty and the
        audit field silently lands as NULL. You discover this during an
        audit, not during development.
      * **It is not async-safe.** Under ASGI, a single thread interleaves
        many requests, so a thread-local can be read by the wrong one. The
        fix is ``contextvars``, which is what this class uses — but any
        third-party code doing the naive ``threading.local()`` version in the
        same project is a live data-attribution bug.
      * **It hides the data flow.** ``created_by`` appearing from nowhere is
        hard to test and hard to reason about.

    The template's default is explicit instead:
    ``BaseModelViewSet.perform_create`` passes the user to ``serializer.save()``.
    That is visible, testable, and behaves identically inside and outside a
    request.

    Enable this only if you have model-layer writes that genuinely cannot
    receive a user — and then make sure the background paths set it explicitly
    via ``set_current_user()``.
    """

    def process_request(self, request):
        from .context import set_current_user

        user = getattr(request, "user", None)
        set_current_user(user if (user and user.is_authenticated) else None)

    def process_response(self, request, response):
        from .context import set_current_user

        # Clear on the way out. Workers are reused across requests; leaving a
        # user behind attributes the next request's writes to the last
        # request's user.
        set_current_user(None)
        return response

    def process_exception(self, request, exception):
        from .context import set_current_user

        set_current_user(None)
        return None
