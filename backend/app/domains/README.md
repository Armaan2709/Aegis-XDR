# Domain-Driven Design (DDD) Architecture

This directory houses bounded contexts for AegisAI XDR.

## Why Domain-Driven Design?
DDD isolates domain entities, rules, services, repositories, and routes within specific business boundaries. This eliminates cross-layer dependency entanglement and allows future microservice extraction.

## Bounded Contexts
- `users/`: Identity management & authentication (Active).
- `alerts/`: Ingestion, scoring & triage (Placeholder).
- `incidents/`: Case lifecycle & root cause metadata (Placeholder).
- `investigations/`: Autonomous AI investigation sessions (Placeholder).
- `playbooks/`: Automated SOAR actions (Placeholder).
- `detections/`: Custom Sigma & YARA detection rule registry (Placeholder).
