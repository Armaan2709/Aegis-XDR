# 🛡️ AegisAI XDR

### Autonomous AI-Powered Extended Detection & Response Platform

<p align="center">
  <strong>Detect → Correlate → Investigate → Enrich → Synthesize → Govern → Respond</strong>
</p>

<p align="center">
  AegisAI XDR is a multi-agent AI security operations platform designed to automate
  SOC investigation workflows while keeping privileged response actions behind
  mandatory human approval and a safe mock execution boundary.
</p>

<p align="center">

![Python](https://img.shields.io/badge/Python-3.13-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-Async-009688?logo=fastapi)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8-005571?logo=elasticsearch)
![Tests](https://img.shields.io/badge/Tests-166%20Passed-success)
![Security Tests](https://img.shields.io/badge/Security%20Tests-23-success)
![License](https://img.shields.io/badge/License-TBD-lightgrey)

</p>

---

## 🚀 Overview

AegisAI XDR is an AI-powered Extended Detection & Response platform that combines:

- 🤖 Multi-agent AI investigation
- 🔎 Threat hunting
- 🧬 Digital forensics and incident response
- 🌐 Threat intelligence enrichment
- 🧠 Detection engineering
- 🎯 MITRE ATT&CK mapping
- 📊 SOC analytics and observability
- 🔐 Role-based access control
- 🧑‍💼 Human-in-the-loop incident governance
- 🛡️ Safe-mock SOAR execution

The platform coordinates **six specialized AI agents** through an **11-stage autonomous investigation pipeline**.

### Core Principle

> **AI can investigate and recommend. Privileged containment requires human authorization.**

---

# 🎯 Problem Statement

Modern Security Operations Centers face several operational challenges:

### Alert Fatigue

Large volumes of security alerts make prioritization and investigation difficult.

### Context Fragmentation

Security telemetry can be distributed across endpoints, authentication systems, networks, cloud workloads, and other sources.

### Investigation Bottlenecks

Manual analysis of process trees, command lines, IOCs, artifacts, timelines, and attack chains can consume significant analyst time.

### Autonomous Execution Risk

Giving an AI system unrestricted access to containment actions can introduce operational and security risks.

### AegisAI XDR Approach

AegisAI XDR combines autonomous investigation with strict governance:

```text
Security Alert
      ↓
AI Investigation
      ↓
Threat Intelligence
      ↓
DFIR Analysis
      ↓
Detection Engineering
      ↓
Incident Synthesis
┌───────────────────────────────────────────────────────────────┐
│                 React SOC Command Center                      │
│                                                               │
│ Dashboard • Alerts • Incidents • Cases • MITRE • Analytics   │
│ Agents • Threat Intel • Approvals • Investigations           │
└───────────────────────────────┬───────────────────────────────┘
                                │
                         REST API / JWT
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                    FastAPI Backend Core                       │
│                                                               │
│ Authentication • RBAC • Security Headers • Rate Limiting    │
│ Request Tracing • API Routing • Health • Observability       │
└───────────────┬───────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────┐
│                       AI Agent Layer                          │
│                                                               │
│ AI Orchestrator                                               │
│ Threat Hunter                                                 │
│ DFIR Investigator                                             │
│ Threat Intelligence Analyst                                   │
│ Detection Rule Generator                                      │
│ Incident Commander                                            │
└───────────────┬───────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────┐
│              11-Stage Investigation Pipeline                 │
└───────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                  HUMAN GOVERNANCE GATE                        │
│                                                               │
│      CaseApproval: PENDING → EXECUTION BLOCKED               │
│                                                               │
│             Human Approval Required                           │
└───────────────────────────────┬───────────────────────────────┘
                                │
                                ▼
┌───────────────────────────────────────────────────────────────┐
│                    SAFE_MOCK_EXECUTION                        │
│                                                               │
│        No destructive real-world actions are executed         │
└───────────────────────────────────────────────────────────────┘
      ↓
Human Approval Gate
🤖 Six AI Agents
Agent	Primary Responsibility
AI Orchestrator	Pipeline coordination, state management and agent dispatch
ThreatHunterAgent	Hypothesis-driven threat hunting and anomaly investigation
DFIRInvestigatorAgent	Digital forensics, process lineage and artifact reconstruction
ThreatIntelAnalystAgent	IOC enrichment, reputation analysis and intelligence synthesis
DetectionRuleGeneratorAgent	Sigma, YARA and Suricata rule generation
IncidentCommanderAgent	Incident synthesis, severity, attack-chain analysis and response planning
      ↓
SAFE_MOCK_EXECUTION

🔄 11-Stage Autonomous Investigation Pipeline
01  TRIAGING
       ↓
02  CORRELATING
       ↓
03  INVESTIGATION_STARTED
       ↓
04  THREAT_HUNTING
       ↓
05  DFIR_ANALYSIS
       ↓
06  THREAT_INTELLIGENCE
       ↓
07  DETECTION_GENERATION
       ↓
08  INCIDENT_SYNTHESIS
       ↓
09  AWAITING_REVIEW
       │
       ├───────────────┐
       │               │
    REJECTED         APPROVED
       │               │
       ▼               ▼
   BLOCKED        10 RESPONSE_EXECUTING
                       │
                       │ SAFE_MOCK_EXECUTION
                       ▼
                  11 COMPLETED
🔐 Security & Governance
Human-in-the-Loop CaseApproval
AI Recommendation
       ↓
CaseApproval = PENDING
       ↓
Execution BLOCKED
       ↓
Human Decision
       │
       ├── REJECTED → BLOCKED
       │
       ├── CANCELLED → BLOCKED
       │
       └── APPROVED
               ↓
       SAFE_MOCK_EXECUTION
🛡️ SAFE_MOCK_EXECUTION
AegisAI XDR uses:
SOAR_EXECUTION_MODE=SAFE_MOCK_EXECUTION
🧪 Synthetic Security Scenarios
AegisAI XDR provides deterministic synthetic scenarios for demonstrations and testing.
1. Credential Compromise
Simulates:
- Credential stuffing
- Authentication abuse
- Lateral movement
- Credential harvesting
MITRE ATT&CK examples:
T1078
T1110
T1003.001

2. Ransomware Simulation
Simulates:
- Shadow copy deletion
- Rapid file encryption
- Recovery disruption
MITRE ATT&CK examples:
T1490
T1486

3. Data Exfiltration
Simulates:
- Sensitive archive staging
- Encrypted outbound communication
- C2/exfiltration behavior
MITRE ATT&CK examples:
T1560.001
T1041

All demonstration telemetry is explicitly isolated as synthetic data.
📊 SOC Command Center
The frontend provides operational views for:
- Dashboard
- Alerts
- Incidents
- Investigations
- Cases
- Approvals
- AI Agents
- Threat Intelligence
- Detection Engineering
- MITRE ATT&CK
- Timeline
- Analytics
- System Health
- Playbooks
- Demo Scenarios
📈 Observability
AegisAI XDR provides operational observability for:
- Component health
- Dependency health
- Request latency
- Request tracing
- Prometheus metrics
- MTTD / MTTR analytics
- PostgreSQL health
- Redis health
- Elasticsearch health
Health Endpoints
GET /api/v1/health/liveness
GET /api/v1/health/readiness
GET /api/v1/health/deps

🧰 Technology Stack
Backend
- Python 3.13
- FastAPI
- SQLAlchemy 2.0
- AsyncPG
- Pydantic v2
- Alembic
- SlowAPI
- Pytest
- Pytest-AsyncIO
Frontend
- React 18
- TypeScript
- Vite
- Tailwind CSS
- TanStack React Query
- Recharts
- Lucide React
Infrastructure
- PostgreSQL 16
- Redis 7
- Elasticsearch 8
- Docker
- Docker Compose
Security
- JWT Authentication
- RBAC
- Security Headers
- Rate Limiting
- Human-in-the-Loop Governance
- Synthetic Telemetry Isolation
- Safe Mock SOAR Execution
📁 Project Structure
AegisAI XDR/
│
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   ├── api/
│   │   ├── case_management/
│   │   ├── core/
│   │   ├── correlation/
│   │   ├── db/
│   │   ├── demo/
│   │   ├── detection_engine/
│   │   ├── domains/
│   │   ├── mitre/
│   │   ├── observability/
│   │   ├── playbooks/
│   │   └── threat_intelligence/
│   │
│   ├── Dockerfile
│   └── pyproject.toml
│
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── context/
│   │   ├── pages/
│   │   └── types/
│   ├── package.json
│   └── vite.config.ts
│
├── docs/
├── tests/
├── scripts/
├── infra/
├── monitoring/
├── docker-compose.yml
├── .env.example
├── .gitignore
└── README.md

⚡ Quick Start
Prerequisites
Python 3.11+
Node.js 18+
npm 9+
Docker
Docker Compose

Required infrastructure:
PostgreSQL 16
Redis 7
Elasticsearch 8

1. Clone Repository
git clone https://github.com/Armaan2709/Aegis-XDR.git
cd Aegis-XDR

2. Configure Environment
cp .env.example .env

Review the environment variables before starting the application.
Never commit .env, API keys, passwords, tokens, certificates, or other secrets.

3. Start Infrastructure
docker compose up -d postgres redis elasticsearch

Verify:
docker compose ps

4. Start Backend
cd backend
source ../venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Backend:
http://localhost:8000

Swagger:
http://localhost:8000/docs

5. Start Frontend
Open another terminal:
cd frontend
npm install
npm run dev

Frontend:
http://localhost:3000

🔑 Development Credentials
Analyst
Username: analyst1
Password: password123

Administrator / Commander
Username: admin@aegis.ai
Password: password123

These credentials are intended for the local demonstration environment only.

🎬 Live Demonstration
Open:
http://localhost:3000/demo

Recommended demonstration flow:
1. Login as analyst1
        ↓
2. Open Demo Scenarios
        ↓
3. Run Credential Compromise
        ↓
4. Observe the investigation pipeline
        ↓
5. Investigation reaches AWAITING_REVIEW
        ↓
6. CaseApproval becomes PENDING
        ↓
7. Attempt privileged approval as analyst
        ↓
8. RBAC returns 403
        ↓
9. Login as administrator
        ↓
10. Open Approvals
        ↓
11. Approve the case
        ↓
12. SAFE_MOCK_EXECUTION
        ↓
13. Investigation completes

Approvals:
http://localhost:3000/approvals

🧪 Testing
Security Tests
python3 -m pytest tests/security -v

Integration Tests
python3 -m pytest tests/integration -v

Full Test Suite
python3 -m pytest tests -v

Frontend Type Checking
cd frontend
npx tsc --noEmit

Production Build
npm run build

✅ Verified Release Baseline
The local release validation included:
Verification	Result
Total Pytest Tests	166 passed
Security Tests	23 passed
Integration Tests	9 passed
Unit Tests	134 passed
TypeScript Errors	0
Frontend Production Build	Passed
Synthetic Demo Scenarios	Validated
CaseApproval Governance	Validated
RBAC Controls	Validated
SAFE_MOCK_EXECUTION	Validated


GitHub Actions may perform additional environment-specific validation. The results above represent the project's local verification baseline.

📚 Documentation
Detailed documentation is available in [`docs/`](./docs/).
Document	Description
[Architecture](./docs/architecture.md)	System architecture and data flow
[AI Agents](./docs/ai_agents.md)	Six-agent architecture
[Autonomous Pipeline](./docs/autonomous_pipeline.md)	11-stage investigation pipeline
[Security Architecture](./docs/security_architecture.md)	Security controls
[Governance](./docs/governance.md)	CaseApproval and human governance
[Threat Model](./docs/threat_model.md)	Threat analysis
[Detection Engine](./docs/detection_engine.md)	Detection rule generation
[Threat Intelligence](./docs/threat_intelligence.md)	IOC enrichment
[DFIR](./docs/dfir.md)	Digital forensics workflow
[SOC Command Center](./docs/soc_command_center.md)	Frontend architecture
[API Documentation](./docs/api.md)	REST API
[Database](./docs/database.md)	Database architecture
[Demo Runbook](./docs/demo_runbook.md)	Demonstration instructions
[Teacher Demo Script](./docs/teacher_demo_script.md)	Instructor walkthrough
[Viva Questions](./docs/viva_questions.md)	Technical viva preparation
[Project Report](./docs/project_report.md)	Complete project report
[Final Release Report](./docs/final_release_report.md)	Release audit


🛡️ Safety Boundaries
AegisAI XDR intentionally separates AI investigation from privileged execution.
AI can:
- Analyze alerts
- Correlate telemetry
- Hunt for threats
- Analyze forensic artifacts
- Enrich IOCs
- Map activity to MITRE ATT&CK
- Generate detection rules
- Synthesize incidents
- Recommend response actions
AI cannot autonomously:
- Execute destructive OS commands
- Isolate real hosts
- Modify real network infrastructure
- Disable real user accounts
- Revoke real credentials
- Perform unrestricted containment
Privileged response actions remain behind the CaseApproval governance boundary.
⚠️ Known Limitations
Safe Mock Execution
SOAR actions are simulated and do not modify real endpoints or networks.
Synthetic Demonstration Data
Demo scenarios use synthetic telemetry with dedicated identifiers to keep demonstrations deterministic and isolated.
Local LLM Fallback
When external LLM providers are not configured, the platform can use deterministic rule-based hypothesis generation for pipeline continuity.
Production Deployment
This repository is primarily designed as a security engineering, research, demonstration, and evaluation platform.
A real production deployment would require environment-specific:
- Secrets management
- Infrastructure hardening
- Identity integration
- Monitoring
- Network security
- Endpoint integrations
- Operational validation
🔭 Future Development
Potential future extensions include:
- Real SIEM integrations
- EDR integrations
- Additional threat intelligence providers
- Production secrets management
- Cloud-native deployment
- Distributed agent execution
- Additional LLM providers
- Expanded detection content
- Additional telemetry sources
- Enterprise identity integrations
👨‍💻 Project
AegisAI XDR
An autonomous AI-powered XDR platform combining:
Multi-Agent AI
      +
Threat Intelligence
      +
DFIR
      +
Detection Engineering
      +
MITRE ATT&CK
      +
SOC Analytics
      +
Human Governance
      +
Safe SOAR

📄 License
License: To be determined by the repository owner.
