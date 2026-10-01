# AegisAI XDR — Enterprise MITRE ATT&CK Mapping Engine

The **MITRE ATT&CK Mapping Engine** serves as the deterministic knowledge layer connecting raw Alerts, Incidents, Evidence artifacts, Timeline events, and Correlation Results to standard MITRE ATT&CK Tactics, Techniques, and Sub-Techniques.

## Key Capabilities

- **Deterministic Signature Mapper**: Processes process names, command line strings, registry keys, and network activity to assign technique IDs (e.g. `T1059.001 PowerShell`, `T1003.001 LSASS Memory`).
- **Matrix Coverage Calculator**: Generates coverage metrics across all 14 tactics and computes technique heatmap matrices for SOC executive dashboards.
- **Local Knowledge Base Layer**: Offline catalog pre-seeded with enterprise tactics, techniques, and sub-techniques, architected for future STIX/TAXII JSON dataset ingestion.
- **Multi-Artifact Linkage**: Associates techniques across Incidents, Evidence, and Timeline events with confidence scoring.

## Architecture

```
backend/app/mitre/
├── __init__.py         # Package exports
├── models.py           # SQLAlchemy entities (Technique, SubTechnique, MitreMapping, Junctions)
├── schemas.py          # Pydantic v2 DTO validation contracts
├── mapper.py           # Deterministic signature matching engine
├── coverage.py         # Coverage metrics & heatmap matrix calculator
├── knowledge_base.py   # Offline ATT&CK catalog & dataset importer
├── repositories.py     # Database query layer
├── services.py         # Application service orchestrating mappings & coverage
├── router.py           # REST API router endpoints (/api/v1/mitre)
└── README.md           # Domain documentation
```
