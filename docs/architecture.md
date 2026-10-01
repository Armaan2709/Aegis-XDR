# AegisAI XDR — System Architecture Specifications

This document outlines the system architecture of the **AegisAI XDR** platform. All diagrams and specifications reflect the actual source code implementation across `backend/app/`, `frontend/src/`, and `tests/`.

---

## 1. High-Level System Architecture

```mermaid
graph TD
    Client["React 18 + TypeScript Frontend"]
    Gateway["FastAPI Gateway / API Router"]
    Auth["JWT Authentication & RBAC Engine"]
    Orchestrator["AI Orchestrator & Pipeline Engine"]
    Domains["Domain Services (Alerts, Incidents, Cases, Playbooks)"]
    Agents["Specialized AI Multi-Agent Cluster"]
    DB[("PostgreSQL 16 (Relational & Audit Store)")]
    Cache[("Redis 7 (Cache & Rate Limiter)")]
    Search[("Elasticsearch 8 (Telemetry Search)")]
    SOAR["SOAR Playbook Engine (SAFE_MOCK_EXECUTION)"]

    Client -->|REST / OpenAPI| Gateway
    Gateway --> Auth
    Auth --> Domains
    Domains --> Orchestrator
    Orchestrator --> Agents
    Domains --> DB
    Domains --> Cache
    Domains --> Search
    Orchestrator --> SOAR
```

---

## 2. Frontend → API → Domain → AI Tiered Architecture

```mermaid
graph LR
    subgraph Presentation Tier
        UI["React SPA Pages / Components"]
        Axios["Axios Interceptor & Auth Header"]
    end

    subgraph API Tier
        Router["FastAPI Router (/api/v1)"]
        Middleware["Correlation ID & Security Headers"]
        RateLimiter["SlowAPI Rate Limiter"]
    end

    subgraph Domain Tier
        Services["Domain Business Logic Services"]
        Repos["Repository Abstraction Layer"]
    end

    subgraph AI Engine Tier
        Pipeline["Autonomous Investigation Pipeline"]
        State["InvestigationState Data Context"]
        Agents["5-Agent Multi-Agent Cluster"]
    end

    UI --> Axios
    Axios --> Router
    Router --> Middleware
    Middleware --> RateLimiter
    RateLimiter --> Services
    Services --> Repos
    Services --> Pipeline
    Pipeline --> State
    Pipeline --> Agents
```

---

## 3. Autonomous Investigation Pipeline (11 Stages)

```mermaid
stateDiagram-v2
    [*] --> CREATED: Ingest Security Alert
    CREATED --> TRIAGING: Evaluate Priority & Severity
    TRIAGING --> CORRELATING: Group Alerts into Incident Graph
    CORRELATING --> INVESTIGATION_STARTED: Initialize InvestigationState
    INVESTIGATION_STARTED --> THREAT_HUNTING: Execute ThreatHunterAgent
    THREAT_HUNTING --> DFIR_ANALYSIS: Execute DFIRInvestigatorAgent
    DFIR_ANALYSIS --> THREAT_INTELLIGENCE: Execute ThreatIntelAnalystAgent
    THREAT_INTELLIGENCE --> DETECTION_GENERATION: Execute DetectionRuleGeneratorAgent
    DETECTION_GENERATION --> INCIDENT_SYNTHESIS: Execute IncidentCommanderAgent
    INCIDENT_SYNTHESIS --> AWAITING_REVIEW: Generate CaseApproval Record
    AWAITING_REVIEW --> RESPONSE_EXECUTING: Approval Granted
    AWAITING_REVIEW --> FAILED: Approval Rejected / Expired
    RESPONSE_EXECUTING --> RESPONSE_COMPLETED: Execute SAFE_MOCK_EXECUTION
    RESPONSE_COMPLETED --> COMPLETED: Record Timeline & Complete Pipeline
    COMPLETED --> [*]
```

---

## 4. Multi-Agent Collaboration Workflow

```mermaid
graph TD
    Alerts["Raw Security Telemetry Alerts"] --> Orchestrator["AI Orchestrator"]
    
    Orchestrator --> Agent1["ThreatHunterAgent"]
    Agent1 -->|Hypotheses & Attack Graph| Orchestrator
    
    Orchestrator --> Agent2["DFIRInvestigatorAgent"]
    Agent2 -->|Process Trees & Timelines| Orchestrator
    
    Orchestrator --> Agent3["ThreatIntelAnalystAgent"]
    Agent3 -->|IOC Reputation & Threat Scores| Orchestrator
    
    Orchestrator --> Agent4["DetectionRuleGeneratorAgent"]
    Agent4 -->|YARA / Sigma Rule Candidates| Orchestrator
    
    Orchestrator --> Agent5["IncidentCommanderAgent"]
    Agent5 -->|Executive Report & Response Plan| Orchestrator
```

---

## 5. InvestigationState Data Flow

```mermaid
graph TD
    Input["Alert Payload"] --> StateInit["InvestigationState Initialization"]
    
    subgraph Shared Context Object
        StateInit --> AlertsField["alerts: List[Dict]"]
        StateInit --> EvidenceField["evidence: List[Dict]"]
        StateInit --> TimelineField["timeline: List[Dict]"]
        StateInit --> AgentResultsField["agent_results: Dict[str, AgentResult]"]
        StateInit --> RiskField["risk_score: float"]
        StateInit --> RecsField["recommendations: List[str]"]
    end

    Agents["Agent Execution Cluster"] -->|Read / Write Mutate| Shared Context Object
    Shared Context Object --> Persistence["Database Persistence & Serialization"]
```

---

## 6. CaseApproval Governance Gate

```mermaid
sequenceDiagram
    autonumber
    participant AI as IncidentCommanderAgent
    participant Gate as CaseApproval Engine
    participant DB as PostgreSQL Database
    participant Analyst as Human SOC Analyst
    participant SOAR as SOAR Engine

    AI->>Gate: Request Response Action (e.g. Host Isolation)
    Gate->>DB: Persist CaseApproval Record (Status = PENDING)
    Gate-->>AI: Pause Pipeline Stage (Status = AWAITING_APPROVAL)
    Analyst->>Gate: Review Justification & Click Approve
    Gate->>DB: Update CaseApproval Status to APPROVED
    Gate->>SOAR: Trigger Response Execution
    SOAR-->>Gate: Execution Result (SAFE_MOCK_EXECUTION)
```

---

## 7. SOAR Safety Boundary Architecture

```mermaid
graph TD
    Trigger["Playbook Execution Request"] --> PolicyCheck["Check SOAR_EXECUTION_MODE"]
    
    PolicyCheck -->|SAFE_MOCK_EXECUTION| MockRunner["Safe Mock SOAR Runner"]
    PolicyCheck -->|Direct Command Prohibited| Rejected["Execution Rejected (400 Bad Request)"]
    
    subgraph Safe Simulation Boundary
        MockRunner --> MockHost["Log Simulated Host Isolation"]
        MockRunner --> MockIP["Log Simulated Firewall Block"]
        MockRunner --> MockAccount["Log Simulated Account Disable"]
    end

    MockRunner --> AuditLog["Record Immutable Audit Event"]
```

---

## 8. Observability & Analytics Architecture

```mermaid
graph TD
    App["FastAPI Backend Services"] --> Logger["Structlog JSON Logger"]
    App --> Metrics["Prometheus Metrics Collector"]
    App --> Tracing["Correlation ID Middleware"]

    Metrics -->|Expose /metrics| Prom["Prometheus Server"]
    Logger -->|Structured JSON Logs| Stdout["Container Logs / Elastic"]
    Tracing -->|X-Correlation-ID Header| Headers["HTTP Client Response Headers"]
```

---

## 9. Authentication & RBAC Authorization Flow

```mermaid
sequenceDiagram
    autonumber
    participant User as Client Browser
    participant Auth as /api/v1/auth/login
    participant JWT as JWT Manager
    participant Guard as RBAC Middleware
    participant Route as Protected API Route

    User->>Auth: Submit Credentials (username, password)
    Auth->>JWT: Verify Bcrypt Hash & Issue Bearer JWT Token
    JWT-->>User: Return Access & Refresh Tokens
    User->>Route: Request Endpoint with Authorization: Bearer <token>
    Route->>Guard: Validate Signature & Extract User Role
    Guard->>Guard: Verify Role Permissions (SOC_ANALYST / INCIDENT_COMMANDER / ADMIN)
    Guard-->>Route: Permission Granted
    Route-->>User: HTTP 200 OK Response Payload
```

---

## 10. Pipeline Failure & State Machine Recovery Flow

```mermaid
stateDiagram-v2
    [*] --> RUNNING: Pipeline Initiated
    RUNNING --> STAGE_FAILED: Stage Execution Error / Exception
    STAGE_FAILED --> RETRYING: Retry Count < Max Retries (3)
    RETRYING --> RUNNING: Retry Stage Execution
    STAGE_FAILED --> PAUSED: Max Retries Exceeded
    PAUSED --> RESUMED: Manual Analyst Resume / State Patch
    RESUMED --> RUNNING: Resume Next Pipeline Stage
    PAUSED --> FAILED: Manual Cancellation
    FAILED --> [*]
```
