# AegisAI XDR End-to-End Security Validation & Demonstration Framework

## Architecture Overview

The `app.demo` package provides a deterministic, reproducible, and non-destructive framework for demonstrating end-to-end security investigation scenarios across the AegisAI XDR platform.

### Core Components
- **`scenarios/`**: Standardized definitions for 3 realistic SOC scenarios:
  1. `credential_compromise`: Initial Access -> Credential Theft -> LSASS Dump -> Lateral Movement.
  2. `ransomware_simulation`: Execution -> Shadow Copy Deletion -> Mass Encryption -> Disablement.
  3. `data_exfiltration`: Discovery -> Encrypted Archiving -> C2 Channel -> Exfiltration.
- **`generators.py`**: Deterministic synthetic telemetry creation (Alerts, Processes, Network Connections, File Mutations).
- **`runner.py`**: `DemoScenarioRunner` managing multi-stage orchestration and 20 non-negotiable system assertion checks.
- **`router.py`**: OpenAPI routes mounted at `/api/v1/demo`.

## Safety Guarantees
- **No Payload Execution**: Synthetic telemetry consists of pure data records without executable binaries.
- **Safe Mock SOAR Execution**: Response playbooks operate exclusively in `SAFE_MOCK_EXECUTION` mode.
- **Mandatory Governance**: `CaseApproval` gates must be explicitly approved before any response action runs.
