"""Distributed tracing with OpenTelemetry and Jaeger."""

import logging

from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from app.config import get_settings

logger = logging.getLogger(__name__)


def setup_tracing(app, db_engine, service_name: str = "soc-platform"):
    """Configure OpenTelemetry tracing with Jaeger exporter and auto-instrumentation."""
    settings = get_settings()

    try:
        from opentelemetry.exporter.jaeger.thrift import JaegerExporter

        jaeger_exporter = JaegerExporter(
            agent_host_name=settings.jaeger_host,
            agent_port=settings.jaeger_port,
        )
        provider = TracerProvider()
        provider.add_span_processor(BatchSpanProcessor(jaeger_exporter))
    except Exception as e:
        logger.warning("Jaeger exporter unavailable, tracing disabled: %s", e)
        provider = TracerProvider()

    trace.set_tracer_provider(provider)

    # Auto-instrument FastAPI
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/health,/health/live,/health/ready,/metrics"
    )

    # Auto-instrument SQLAlchemy (use sync_engine for async engine)
    engine_to_instrument = getattr(db_engine, 'sync_engine', db_engine)
    SQLAlchemyInstrumentor().instrument(
        engine=engine_to_instrument,
        service=service_name
    )

    # Auto-instrument HTTPX (for external API calls)
    HTTPXClientInstrumentor().instrument()

    return trace.get_tracer(service_name, settings.service_version)
