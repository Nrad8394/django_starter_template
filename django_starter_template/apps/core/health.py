"""
Health endpoints.

Two endpoints, because orchestrators ask two different questions and
conflating them causes outages.

``/health/`` — liveness. "Is this process alive?"
    Touches nothing external. Returns 200 as long as the Python process can
    serve a request.

    This distinction is the important one. A liveness probe that checks the
    database will fail during a brief database blip, the orchestrator will
    conclude the container is broken and kill it, the replacement will fail
    the same check, and a thirty-second database hiccup becomes a full
    outage with a restart storm on top. Liveness answers "should you restart
    me", and the answer to that is almost never yes because a dependency is
    slow.

``/readyz/`` — readiness. "Should traffic be routed here?"
    Checks the database, cache and broker. Failing here removes the instance
    from the load balancer without killing it, so it rejoins automatically
    when the dependency recovers.

Kubernetes: ``livenessProbe`` → ``/health/``, ``readinessProbe`` → ``/readyz/``.
Docker Compose / ECS with a single check: use ``/health/``.

Both are exempt from authentication — a probe has no credentials — and both
are deliberately terse. A health endpoint that reports library versions or
settings is a free reconnaissance endpoint for anyone who finds it.
"""

import logging

from django.conf import settings
from django.core.cache import cache
from django.db import connections
from django.db.utils import OperationalError
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import status
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes,
    throttle_classes,
)
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

logger = logging.getLogger(__name__)


@extend_schema(
    summary="Liveness probe",
    description=(
        "Returns 200 while the process can serve requests. Checks no external "
        "dependency by design — see the module docstring."
    ),
    responses={200: OpenApiResponse(description="Process is alive")},
    auth=[],
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
# No throttle: probes run every few seconds and would otherwise exhaust the
# anonymous rate limit, turning the health check itself into the outage.
@throttle_classes([])
def liveness(request):
    return Response({"status": "ok"}, status=status.HTTP_200_OK)


def _check_database(alias="default"):
    try:
        with connections[alias].cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return True, None
    except OperationalError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 - a probe must never itself raise
        return False, str(exc)


def _check_cache():
    try:
        key = "healthcheck:probe"
        cache.set(key, "1", timeout=5)
        # Round-trip rather than a bare set(): several cache backends accept a
        # write and silently discard it when they are unhealthy, so a
        # write-only check reports green on a broken cache.
        if cache.get(key) != "1":
            return False, "cache write succeeded but read returned nothing"
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _check_broker():
    try:
        from django_starter_template.celery_app import app as celery_app

        conn = celery_app.connection()
        conn.ensure_connection(max_retries=0, timeout=2)
        conn.release()
        return True, None
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


#: Checks run by /readyz/. Drop entries you do not deploy — a readiness probe
#: that fails on a service you never started is worse than no probe.
READINESS_CHECKS = {
    "database": _check_database,
    "cache": _check_cache,
    # "broker": _check_broker,   # enable when Celery is part of the deployment
}


@extend_schema(
    summary="Readiness probe",
    description=(
        "Verifies the dependencies needed to serve real traffic. Returns 503 "
        "when any check fails, so the load balancer stops routing here "
        "without the container being restarted."
    ),
    responses={
        200: OpenApiResponse(description="Ready for traffic"),
        503: OpenApiResponse(description="A dependency is unavailable"),
    },
    auth=[],
)
@api_view(["GET"])
@authentication_classes([])
@permission_classes([AllowAny])
@throttle_classes([])
def readiness(request):
    results = {}
    healthy = True

    for name, check in READINESS_CHECKS.items():
        ok, error = check()
        results[name] = "ok" if ok else "error"
        if not ok:
            healthy = False
            # The reason goes to the logs, not the response. An unauthenticated
            # endpoint that echoes connection strings and hostnames from
            # exception text hands an attacker a map of your infrastructure.
            logger.error("Readiness check %r failed: %s", name, error)

    return Response(
        {"status": "ok" if healthy else "degraded", "checks": results},
        status=(
            status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
    )


@extend_schema(
    summary="Build and version information",
    responses={200: OpenApiResponse(description="Version info")},
)
@api_view(["GET"])
def version(request):
    """
    Which build is running.

    Authenticated on purpose. Knowing the exact version of a deployment is
    genuinely useful during an incident and genuinely useful to someone
    matching your version against a CVE list. Requiring a login is a
    reasonable middle ground; drop the endpoint entirely if you would rather
    not publish it at all.
    """
    return Response(
        {
            "version": getattr(settings, "API_VERSION", "unknown"),
            "environment": getattr(settings, "DJANGO_ENV", "unknown"),
        }
    )
