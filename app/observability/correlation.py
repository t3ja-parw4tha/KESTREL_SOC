"""Correlation ID middleware for request tracing across async context."""

from contextvars import ContextVar
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware

# Context variable for request-scoped correlation ID
request_id_var: ContextVar[str] = ContextVar(
    'request_id',
    default='no-request-id'
)


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """
    Assigns a unique request ID to every request.
    Propagates through async context automatically.
    All log statements within a request automatically include the request ID.
    """

    async def dispatch(self, request, call_next):
        # Use provided ID or generate new one
        request_id = request.headers.get(
            "X-Request-ID",
            str(uuid.uuid4())
        )

        # Validate format if provided
        if "X-Request-ID" in request.headers:
            try:
                uuid.UUID(request_id)
            except ValueError:
                request_id = str(uuid.uuid4())

        # Set in context var (propagates to all async calls)
        token = request_id_var.set(request_id)

        # Bind to structlog context
        structlog.contextvars.bind_contextvars(request_id=request_id)

        try:
            response = await call_next(request)
            if "X-Request-ID" not in response.headers:
                response.headers["X-Request-ID"] = request_id
            return response
        finally:
            # Clean up context
            request_id_var.reset(token)
            structlog.contextvars.clear_contextvars()
