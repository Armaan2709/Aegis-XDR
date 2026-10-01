# AegisAI XDR — Enterprise Observability & SOC Analytics

The Observability domain provides real-time, data-driven operational visibility across the AegisAI XDR platform.

## Architecture

- **`schemas.py`**: Pydantic V2 DTOs for metrics, MTTD/MTTR, pipeline stage performance, AI agent runs, case workloads, and system health.
- **`collectors.py`**: Domain-specific metrics collectors extracting real data from PostgreSQL, Redis, Elasticsearch, and pipeline contexts.
- **`services.py`**: `SOCAnalyticsService` aggregating platform metrics and calculating conversion funnels and time-window filters.
- **`tracing.py`**: OpenTelemetry-ready trace context adapter preserving correlation IDs while redacting credentials and sensitive evidence.
- **`exporters.py`**: Prometheus text-format metric exporter (`aegis_alerts_total`, `aegis_mttd_seconds`, `aegis_agent_runs_total`).
- **`router.py`**: FastAPI router exposing 12 REST observability endpoints + `/metrics`.
