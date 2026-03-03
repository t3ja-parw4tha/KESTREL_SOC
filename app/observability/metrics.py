"""Prometheus metrics for SOC platform."""

from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
from prometheus_fastapi_instrumentator import Instrumentator

# Registry
registry = CollectorRegistry()

# Alert metrics
ALERTS_INGESTED = Counter(
    'soc_alerts_ingested_total',
    'Total alerts ingested',
    ['source', 'severity', 'category'],
    registry=registry
)

ALERTS_BY_STATUS = Gauge(
    'soc_alerts_by_status',
    'Current alert counts by status',
    ['status'],
    registry=registry
)

ACTIVE_INCIDENTS = Gauge(
    'soc_active_incidents_total',
    'Number of active incidents',
    registry=registry
)

# Decision engine metrics
DECISION_ENGINE_DURATION = Histogram(
    'soc_decision_engine_duration_seconds',
    'Time to run decision engine',
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0],
    registry=registry
)

DECISION_RISK_SCORES = Histogram(
    'soc_decision_risk_scores',
    'Distribution of risk scores',
    buckets=[10, 25, 50, 75, 90, 100],
    registry=registry
)

# AI metrics
AI_GENERATION_DURATION = Histogram(
    'soc_ai_generation_duration_seconds',
    'Time to generate AI summary',
    ['provider', 'model'],
    buckets=[1, 5, 10, 30, 60],
    registry=registry
)

AI_GENERATION_TOTAL = Counter(
    'soc_ai_generations_total',
    'Total AI generations',
    ['provider', 'status'],
    registry=registry
)

AI_TOKEN_USAGE = Counter(
    'soc_ai_tokens_total',
    'Total AI tokens consumed',
    ['provider', 'type'],
    registry=registry
)

AI_COST_USD = Counter(
    'soc_ai_cost_usd_total',
    'Estimated AI cost in USD',
    ['provider'],
    registry=registry
)

# Enrichment metrics
ENRICHMENT_DURATION = Histogram(
    'soc_enrichment_duration_seconds',
    'Time to enrich alert',
    ['provider'],
    buckets=[0.1, 0.5, 1.0, 5.0, 10.0],
    registry=registry
)

ENRICHMENT_CACHE_HITS = Counter(
    'soc_enrichment_cache_hits_total',
    'Enrichment cache hits',
    ['provider'],
    registry=registry
)

ENRICHMENT_API_ERRORS = Counter(
    'soc_enrichment_api_errors_total',
    'Enrichment API errors',
    ['provider', 'error_type'],
    registry=registry
)

# Connector metrics
CONNECTOR_INGESTION_DURATION = Histogram(
    'soc_connector_ingestion_duration_seconds',
    'Time for connector to fetch and ingest logs',
    ['connector'],
    registry=registry
)

CONNECTOR_EVENTS_FETCHED = Counter(
    'soc_connector_events_fetched_total',
    'Events fetched by connector',
    ['connector', 'status'],
    registry=registry
)

CONNECTOR_LAST_RUN = Gauge(
    'soc_connector_last_run_timestamp',
    'Unix timestamp of last successful connector run',
    ['connector'],
    registry=registry
)

# Playbook metrics
PLAYBOOK_EXECUTIONS = Counter(
    'soc_playbook_executions_total',
    'Total playbook executions',
    ['playbook', 'result'],
    registry=registry
)

PLAYBOOK_DURATION = Histogram(
    'soc_playbook_duration_seconds',
    'Time to execute playbook',
    ['playbook'],
    registry=registry
)

# Security metrics
AUTH_ATTEMPTS = Counter(
    'soc_auth_attempts_total',
    'Authentication attempts',
    ['result'],
    registry=registry
)

RATE_LIMIT_HITS = Counter(
    'soc_rate_limit_hits_total',
    'Rate limit violations',
    ['endpoint'],
    registry=registry
)

SUSPICIOUS_REQUESTS = Counter(
    'soc_suspicious_requests_total',
    'Suspicious request patterns detected',
    ['pattern_type'],
    registry=registry
)

# Database metrics
DB_QUERY_DURATION = Histogram(
    'soc_db_query_duration_seconds',
    'Database query duration',
    ['operation', 'table'],
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
    registry=registry
)

DB_CONNECTION_POOL = Gauge(
    'soc_db_pool_size',
    'Database connection pool size',
    ['state'],
    registry=registry
)


def setup_metrics(app) -> Instrumentator:
    """Configure Prometheus instrumentator and expose /metrics endpoint."""
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/health/live", "/health/ready", "/metrics"],
        inprogress_name="soc_inprogress_requests",
        inprogress_labels=True,
    )
    instrumentator.instrument(app)
    instrumentator.expose(app, endpoint="/metrics")
    return instrumentator
