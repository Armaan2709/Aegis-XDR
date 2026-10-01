# AegisAI XDR — Telemetry, Metrics & Observability Monitoring

This directory contains configuration files for platform health observability, metric collectors, and alerting dashboards.

## Directory Contents

- `prometheus/`: Prometheus metric scrapers and alerting rules for backend API latency, error rates, and task queue depth.
- `grafana/`: Pre-configured Grafana dashboard JSON models for real-time SOC platform operations.
- `vector/` / `fluentbit/`: Log shipper configurations routing platform logs to Elasticsearch.
