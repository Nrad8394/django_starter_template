# syntax=docker/dockerfile:1.7
# ^ Enables BuildKit cache mounts and heredocs. BuildKit is the default engine
#   in Docker >= 23. On older installs: DOCKER_BUILDKIT=1 docker build ...
#
# =============================================================================
# Django backend — production image
#
# Stages
#   base          shared env, virtualenv path
#   builder       compilers + headers; builds wheels into the virtualenv
#   production    runtime only — no compilers, no headers, non-root
#
# Build
#   docker build -t myapp:latest .
#   docker build --build-arg VERSION=1.2.3 \
#                --build-arg VCS_REF=$(git rev-parse --short HEAD) \
#                --build-arg BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) .
#
# The two-stage split is the point: build tools are ~400 MB and are also the
# most useful thing an attacker can find on a compromised host. Nothing from
# `builder` reaches the final image except the virtualenv.
# =============================================================================

ARG PYTHON_VERSION=3.12
ARG APP_PORT=8000
ARG UID=1000
ARG GID=1000
ARG UV_VERSION=0.5.8
ARG BASE_IMAGE=python:${PYTHON_VERSION}-slim-bookworm

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION


# =============================================================================
# STAGE 1 — base
# =============================================================================
FROM ${BASE_IMAGE} AS base

ARG APP_PORT

ENV VENV_PATH=/opt/venv
ENV PATH="${VENV_PATH}/bin:$PATH"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Print a Python traceback on SIGSEGV/SIGFPE. Costs nothing and turns an
    # otherwise silent container death into something diagnosable.
    PYTHONFAULTHANDLER=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PORT=${APP_PORT}

WORKDIR /app


# =============================================================================
# STAGE 2 — builder
#
# Layer order determines cache hit rate:
#   A  venv           busted only by a base-image bump
#   B  uv             busted only by UV_VERSION
#   C  dependencies   busted only by pyproject.toml / uv.lock
# Application source is never copied here, so editing a view does not
# reinstall anything.
# =============================================================================
FROM base AS builder

ARG UV_VERSION

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        pkg-config \
        python3-dev \
        libpq-dev \
        libffi-dev \
        curl \
        ca-certificates
    # Add here only if you need them — each is tens to hundreds of MB:
    #   WeasyPrint / Pillow: libjpeg-dev libpng-dev libfreetype6-dev
    #                        libharfbuzz-dev libfribidi-dev
    #   GeoDjango:           libgdal-dev libgeos-dev libproj-dev
    #   numpy / scipy:       libopenblas-dev liblapack-dev gfortran
    #   VCS requirements:    git

# Layer A
RUN python -m venv "${VENV_PATH}"

# Layer B
RUN --mount=type=cache,target=/root/.cache/uv \
    pip install --no-cache-dir "uv==${UV_VERSION}"

# Layer C — only the manifests, so source edits do not invalidate it.
COPY pyproject.toml uv.lock* ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --python "${VENV_PATH}/bin/python" .


# =============================================================================
# STAGE 3 — production
# =============================================================================
FROM base AS production

ARG UID
ARG GID
ARG APP_PORT
ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

# Create the user before any COPY so --chown can name it directly instead of
# needing a recursive chown pass over the whole tree afterwards.
RUN groupadd --gid "${GID}" appgroup && \
    useradd --uid "${UID}" --gid "${GID}" --no-log-init \
            --create-home --shell /usr/sbin/nologin appuser

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libpq5 \
        # PID 1 in a container does not reap zombies or forward signals the
        # way init does. Without this, SIGTERM never reaches gunicorn and
        # every deploy ends in a 10-second SIGKILL instead of a graceful drain.
        dumb-init \
        curl \
        ca-certificates && \
    # Drop setuid/setgid bits: nothing in this image needs privilege
    # escalation, and leaving them is free attack surface.
    find /usr /bin /sbin /lib -xdev \( -perm /4000 -o -perm /2000 \) \
        -exec chmod -s {} + 2>/dev/null || true

ENV PYTHONPATH=/app

COPY --from=builder --chown=appuser:appgroup /opt/venv /opt/venv

# Source last — it changes on every build, so it must not sit above anything
# expensive.
COPY --chown=appuser:appgroup . /app/

RUN chown appuser:appgroup /app && \
    find /app -type d -exec chmod 0750 {} + && \
    find /app -type f -exec chmod 0640 {} + && \
    find /app -name "*.sh" -exec chmod 0750 {} + && \
    mkdir -p /app/logs /app/staticfiles /app/media && \
    chown -R appuser:appgroup /app/logs /app/staticfiles /app/media && \
    chmod 0770 /app/logs /app/media

# Collect static at build time so the runtime image is immutable and the
# container starts without needing write access or a database.
#
# The placeholder SECRET_KEY exists only to satisfy settings import — it is
# never used to sign anything, is not present at runtime, and does not end up
# in a layer that matters. `DJANGO_ENV=development` avoids production's
# required-variable checks (which want a real database URL).
RUN DJANGO_ENV=development \
    SECRET_KEY=build-time-placeholder-not-used-at-runtime \
    python manage.py collectstatic --noinput --clear || \
    echo "collectstatic skipped — run it at deploy time instead"

RUN <<'EOF' /bin/sh
cat > /usr/local/bin/docker-entrypoint.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail

# New files created at runtime get 0640 / dirs 0750 rather than world-readable.
umask 0027

# Derive worker count at start rather than baking it in, so one image runs
# correctly on a 2-core and a 16-core host. The 2N+1 rule is gunicorn's own
# guidance for sync workers.
if [ -z "${GUNICORN_WORKERS:-}" ]; then
    export GUNICORN_WORKERS=$(( $(nproc 2>/dev/null || echo 2) * 2 + 1 ))
fi
export GUNICORN_THREADS="${GUNICORN_THREADS:-4}"
export GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-120}"
export GUNICORN_LOG_LEVEL="${GUNICORN_LOG_LEVEL:-info}"
# Recycle workers periodically. Bounds the impact of any slow memory leak in
# the app or a dependency; the jitter stops every worker restarting at once.
export GUNICORN_MAX_REQUESTS="${GUNICORN_MAX_REQUESTS:-1000}"
export GUNICORN_MAX_REQUESTS_JITTER="${GUNICORN_MAX_REQUESTS_JITTER:-100}"
export PORT="${PORT:-8000}"

# Fail loudly at start rather than serving 500s once traffic arrives.
_missing=""
for _var in SECRET_KEY DATABASE_URL; do
    eval "_val=\"\${${_var}:-}\""
    [ -z "${_val}" ] && _missing="${_missing} ${_var}"
done
if [ -n "${_missing}" ]; then
    printf '[entrypoint] FATAL: missing required env vars:%s\n' "${_missing}" >&2
    exit 1
fi

# Migrations are deliberately NOT run here. With more than one replica, every
# container racing `migrate` on startup is a recipe for lock contention and
# half-applied schemas. Run it as a separate one-shot job in your deploy
# pipeline. Set RUN_MIGRATIONS_ON_START=true only for single-instance setups.
if [ "${RUN_MIGRATIONS_ON_START:-false}" = "true" ]; then
    echo "[entrypoint] running migrations"
    python manage.py migrate --noinput
fi

printf '[entrypoint] env=%s workers=%s threads=%s port=%s\n' \
    "${DJANGO_ENV:-development}" "${GUNICORN_WORKERS}" \
    "${GUNICORN_THREADS}" "${PORT}"

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec gunicorn django_starter_template.wsgi:application \
    --bind                "0.0.0.0:${PORT}" \
    --workers             "${GUNICORN_WORKERS}" \
    --threads             "${GUNICORN_THREADS}" \
    --timeout             "${GUNICORN_TIMEOUT}" \
    --max-requests        "${GUNICORN_MAX_REQUESTS}" \
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER}" \
    --access-logfile      - \
    --error-logfile       - \
    --log-level           "${GUNICORN_LOG_LEVEL}"
SCRIPT
chmod 0755 /usr/local/bin/docker-entrypoint.sh
EOF

EXPOSE ${APP_PORT}

# Points at the health endpoint from apps/core/urls.py. That view must not
# touch the database: a health check that fails when the database is briefly
# unavailable causes the orchestrator to kill an otherwise-fine container,
# turning a blip into an outage. Check dependencies at /readyz instead.
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health/" || exit 1

USER appuser:appgroup

LABEL org.opencontainers.image.created="${BUILD_DATE:-unknown}" \
      org.opencontainers.image.revision="${VCS_REF:-unknown}" \
      org.opencontainers.image.version="${VERSION:-unknown}" \
      org.opencontainers.image.title="django-starter-template" \
      org.opencontainers.image.base.name="python:${PYTHON_VERSION}-slim-bookworm"

ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/local/bin/docker-entrypoint.sh"]
CMD []
