# AegisAI XDR — Enterprise Deterministic Correlation Engine

The **Correlation Engine** aggregates raw, high-volume security alerts from SIEM, EDR, Network, and Cloud log sources into unified, actionable **Incidents**.

## Features

- **Deterministic Rule Evaluation**: Group alerts based on matching entities (Hostname, IP address, Username, Process, Hash) within configurable time windows.
- **Alert Deduplication**: Cryptographic fingerprinting (`SHA256`) to suppress duplicate alert floods.
- **Deterministic Risk Aggregation**:
  $$ \text{Aggregated Risk} = \min\left(100, \left( \max(\text{Alert Risks}) + 10 \times \ln(\text{Count} + 1) \right) \times \text{Rule Weight} \right) $$
- **Entity Relationship Graphs**: Graph representation modeling connections between Alerts, Incidents, Hosts, Users, IPs, and Evidence artifacts.
- **Clean Architecture & DDD**: Fully decoupled repositories, services, Pydantic v2 schemas, and FastAPI REST endpoints.

## Architecture

```
backend/app/correlation/
├── __init__.py       # Package exports
├── engine.py         # Correlation engine core & risk calculation formulas
├── rules.py          # Deterministic rules specs & default enterprise templates
├── graph.py          # Entity node & edge relationship network graph models
├── schemas.py        # Pydantic v2 DTO validation contracts
├── repositories.py   # Database query layer for alerts & incident associations
├── services.py       # Application service orchestrating correlation runs
├── router.py         # REST API router endpoints (/api/v1/correlation)
└── README.md         # Domain documentation
```
