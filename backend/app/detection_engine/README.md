# AegisAI XDR — Enterprise Detection Rule Engine

The **Detection Rule Engine** manages detection rule lifecycles across SIEM, EDR, and IDS formats (**Sigma YAML**, **YARA**, **Suricata**, and **Custom Rules**).

## Core Capabilities

- **Multi-Format Rule Parsing**: Extracts title, severity, tags, and structure from Sigma YAML, YARA memory signatures, and Suricata network alerts.
- **Deterministic Validation**: Syntax checking, required fields verification, duplicate title detection, and metadata compliance.
- **Version Control & Diffs**: Full change history tracking, line-by-line unified diff comparisons, and version rollbacks.
- **Dry-Run Rule Testing**: Evaluates rules against sample payloads and benchmarks execution speed (ms) without affecting live traffic.
- **Centralized Registry & Templates**: Reusable templates for standard attack vectors.

## Module Structure

```
backend/app/detection_engine/
├── __init__.py         # Package exports
├── models.py           # SQLAlchemy entities (DetectionRule, RuleVersion, RuleExecution, etc.)
├── schemas.py          # Pydantic v2 DTO validation contracts
├── repositories.py     # Database query layer
├── services.py         # Application service orchestrating lifecycle & versioning
├── router.py           # REST API endpoints (/api/v1/detection-rules)
├── rule_parser.py      # Sigma, YARA, Suricata & Custom parsers
├── rule_validator.py   # Syntax & metadata validator
├── rule_versions.py    # Version control manager & diff engine
├── rule_tester.py      # Dry-run execution benchmark framework
├── rule_registry.py    # Rule templates & catalog registry
└── README.md           # Domain documentation
```
