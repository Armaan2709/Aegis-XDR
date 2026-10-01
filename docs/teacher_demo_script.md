# AegisAI XDR — Evaluator & Teacher Demonstration Guide (Primary & Backup Tracks)

This guide provides both a **Primary Live Interactive Track** and a **Backup Fallback Track** for presenting **AegisAI XDR** to professors, technical evaluators, and project committees.

---

## 🛣️ Path 1: Primary Live Interactive Demonstration (15 Minutes)

### 🕒 00:00–01:00 — Problem Statement & Operational Challenge
- **CLICK**: Open browser to `http://localhost:3000/login`.
- **SHOW**: Clean, enterprise authentication interface with AegisAI XDR branding and JWT security badge.
- **SAY**:
  > *"Good morning professors and evaluators. Modern Security Operations Centers face three critical vulnerabilities: severe alert fatigue from thousands of disconnected logs, high MTTR due to manual process tree and timeline reconstruction, and dangerous automated SOAR tools that risk tearing down core production infrastructure without human oversight. Today I present AegisAI XDR — an autonomous cyber defense platform engineered to solve these exact challenges."*
- **TECHNICAL POINT**: Modern SOC Operational Bottlenecks & Strategic Solution Vision.

---

### 🕒 01:00–02:00 — Platform Architecture & Technology Stack
- **CLICK**: Log in with credentials (`analyst1` / `password123`) to navigate to `/`.
- **SHOW**: AegisAI XDR Executive Dashboard with live system metrics.
- **SAY**:
  > *"AegisAI XDR is built on a clean, domain-driven microservices backend utilizing FastAPI, PostgreSQL, Redis, and Elasticsearch, paired with a React 18 TypeScript frontend. Rather than relying on a single generic LLM, AegisAI XDR orchestrates a specialized 5-agent AI cluster using state machine graphs."*
- **TECHNICAL POINT**: Tiered Domain-Driven Architecture & Multi-Agent Graph Design.

---

### 🕒 02:00–03:00 — SOC Dashboard Navigation
- **CLICK**: Click through `/alerts`, `/incidents`, and `/system-health`.
- **SHOW**: Real-time alerts table, correlated incident graphs, and component health monitoring latencies.
- **SAY**:
  > *"Here in our command center, we observe live telemetry stream processing. Our backend continuously monitors health latencies across PostgreSQL, Redis, and Elasticsearch. Notice our strict RBAC badges enforcing role permissions across the entire platform."*
- **TECHNICAL POINT**: Observability, Health Monitoring & RBAC Authorization.

---

### 🕒 03:00–05:00 — Synthetic Attack Launch
- **CLICK**: Navigate to `/demo` (`Demo Scenarios`). Ensure `Auto-Approve Governance Gate` checkbox is **UNCHECKED**. Click **RUN SYNTHETIC SCENARIO** under `Credential Compromise & LSASS Dump`.
- **SHOW**: Synthetic Isolation Banners light up; execution spinner begins compiling pipeline state.
- **SAY**:
  > *"To demonstrate our pipeline safely and deterministically, we launch a synthetic Credential Compromise attack vector. Notice our purple and amber safety banners — all demonstration telemetry is tagged with synthetic IDs, completely isolated from live production data."*
- **TECHNICAL POINT**: Deterministic Synthetic Telemetry Ingestion & Safety Isolation.

---

### 🕒 05:00–07:00 — AI Multi-Agent Pipeline & Threat Hunting
- **CLICK**: Click the **11-Stage Pipeline** tab and then switch to the **AI Agent Findings** tab.
- **SHOW**: 11-stage progress tracker highlighting `Stage 4: THREAT_HUNTING` (ThreatHunterAgent).
- **SAY**:
  > *"As the pipeline executes, the ThreatHunterAgent analyzes alert clusters, formulates hypotheses, and maps techniques directly to MITRE ATT&CK tactics T1078 and T1003.001."*
- **TECHNICAL POINT**: Autonomous Threat Hunting & MITRE ATT&CK Mapping.

---

### 🕒 07:00–08:30 — DFIR & Threat Intelligence Analysis
- **CLICK**: Inspect `DFIRInvestigatorAgent` and `ThreatIntelAnalystAgent` cards under **AI Agent Findings**.
- **SHOW**: Structured JSON output displaying process parent-child links (`cmd.exe` → `powershell.exe`) and IP reputation scores.
- **SAY**:
  > *"Next, the DFIRInvestigatorAgent reconstructs the execution process tree and decodes Base64 PowerShell commands. Simultaneously, the ThreatIntelAnalystAgent queries IOC reputation feeds, computing provider consensus for suspicious IP address 185.220.101.5."*
- **TECHNICAL POINT**: Process Tree Reconstruction & Threat Intelligence Provider Consensus.

---

### 🕒 08:30–10:00 — Detection Rule Synthesis
- **CLICK**: Inspect `DetectionGeneratorAgent` finding card, then open `/detections` in a new tab.
- **SHOW**: Synthesized Sigma rule candidate for LSASS memory dumping flagged in `CANDIDATE` status.
- **SAY**:
  > *"The DetectionRuleGeneratorAgent synthesizes a production-grade Sigma rule based on observed attack evidence. Crucially, as shown in our rule console, candidate rules are stored strictly in CANDIDATE status — they are never automatically deployed without human analyst dry-run verification."*
- **TECHNICAL POINT**: Automated Detection Rule Synthesis & Candidate Safety Boundary.

---

### 🕒 10:00–11:30 — Incident Commander Synthesis
- **CLICK**: Return to `/demo` tab and inspect `IncidentCommanderAgent` card.
- **SHOW**: Executive summary, overall risk score `88.5 / 100`, and proposed response plan (`ISOLATE_HOST`).
- **SAY**:
  > *"The IncidentCommanderAgent aggregates all agent outputs, computes a risk score of 88.5, and formulates an executive summary. However, notice that the pipeline automatically halts at Stage 9."*
- **TECHNICAL POINT**: Multi-Agent Synthesis & Risk Scoring.

---

### 11:30–13:00 — CaseApproval Governance Gate Enforcement
- **CLICK**: Highlight the prominent amber **HUMAN GOVERNANCE APPROVAL REQUIRED** warning banner on `/demo`.
- **SHOW**: Banner stating *"CaseApproval record pending analyst review. SOAR response actions remain safely paused."*
- **SAY**:
  > *"Here is the cornerstone of AegisAI XDR's security architecture: the mandatory CaseApproval governance gate. The AI recommended isolating host WORKSTATION-9, but the platform refuses to execute privileged SOAR playbooks without explicit human sign-off. PENDING means BLOCKED."*
- **TECHNICAL POINT**: Mandatory Human-in-the-Loop Governance (`CaseApproval`).

---

### 🕒 13:00–14:00 — Safe Mock SOAR Execution
- **CLICK**: Click the **APPROVE SIMULATED SOAR** button on the warning banner.
- **SHOW**: Approval status transitions to `APPROVED`; pipeline advances to Stage 10 (`RESPONSE_EXECUTING`) and Stage 11 (`COMPLETED`).
- **SAY**:
  > *"Once granted human approval, the playbook executes. Notice our SOAR execution badge: SAFE_MOCK_EXECUTION. AegisAI XDR logs the containment sequence and updates database audit logs without executing destructive host commands."*
- **TECHNICAL POINT**: Safe Mock SOAR Execution Boundary & Auditability.

---

### 🕒 14:00–15:00 — 20-Point Assertions, Analytics & Conclusion
- **CLICK**: Click the **20-Point Assertions** tab (`20/20 Passed`), then navigate to `/analytics`.
- **SHOW**: 20/20 green checkmarks confirming assertion validity; analytics graphs showing MTTD/MTTR improvements.
- **SAY**:
  > *"To verify complete system integrity, our 20-point assertion validator checks every state transition, agent output, and governance invariant — achieving a perfect 20 out of 20 score. In summary, AegisAI XDR proves that autonomous multi-agent AI can dramatically accelerate cyber defense while preserving absolute human governance and infrastructure safety. Thank you, and I welcome your questions."*
- **TECHNICAL POINT**: Automated Assertion Validation & System Conclusion.

---

## 🛠️ Path 2: Backup Fallback Demonstration (Command Line / API Track)

If frontend rendering or local UI display encounters an unexpected environment failure during live presentation, immediately switch to the CLI/API fallback track.

### Step 1: Execute Synthetic Scenario via Terminal
```bash
curl -X POST "http://localhost:8000/api/v1/demo/run" \
  -H "Content-Type: application/json" \
  -d '{"scenario_id": "credential_compromise", "auto_approve": false}'
```

### Step 2: Display Structured JSON Execution Result
```bash
curl -X GET "http://localhost:8000/api/v1/demo/report/credential_compromise" | python3 -m json.tool
```

### Step 3: Demonstrate Automated Pytest Security Verification
```bash
python3 -m pytest tests/security/test_approval_bypass.py -v
python3 -m pytest tests/security/test_demo_security.py -v
```

- **SAY**:
  > *"As demonstrated via our REST API and automated security test suite, AegisAI XDR executes the 11-stage pipeline, logs agent outputs, enforces CaseApproval governance blocking, and executes mock SOAR containment under deterministic test benchmarks."*
