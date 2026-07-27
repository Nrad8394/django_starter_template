"""
Per-request context, implemented with ``contextvars``.

Only used when ``CurrentUserMiddleware`` is enabled — read its docstring
first; the template's default is to pass the user explicitly instead.

Why ``contextvars`` and not ``threading.local()``
-------------------------------------------------
Under WSGI, one request owns one thread for its lifetime and a thread-local
works. Under ASGI it does not: a single thread runs many coroutines
concurrently, so request A can read the value request B just wrote. The result
is audit fields attributed to the wrong user — a bug that appears only under
concurrency, only in production, and produces plausible-looking wrong data
rather than an error.

``contextvars`` is the async-aware equivalent and works correctly under both.
There is no reason to use ``threading.local()`` for this on Python 3.7+.
"""

from contextvars import ContextVar

_current_user: ContextVar = ContextVar("current_user", default=None)


def set_current_user(user):
    """Set the user for the current request/task context."""
    _current_user.set(user)


def get_current_user():
    """
    Return the context's user, or ``None``.

    ``None`` outside a request — background tasks, management commands,
    migrations, and the shell. Callers must handle that; treating it as "no
    user" is correct, treating it as "impossible" is how audit fields end up
    NULL in production.
    """
    return _current_user.get()
