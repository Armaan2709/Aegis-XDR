# AegisAI XDR — SOC Command Center Page & Route Specifications

This document specifies the 16 frontend page containers and routes in the **AegisAI XDR** React application (`frontend/src/pages/`).

---

## 🖥️ 1. `/login` — Analyst Authentication Portal
- **Purpose**: Authenticates SOC analysts and issues JWT access tokens.
- **Data Source**: User credential form inputs.
- **Main Actions**: Submit login form, toggle password visibility, clear error messages.
- **Relevant APIs**: `POST /api/v1/auth/login`.
- **Role & Security Restrictions**: Public unauthenticated endpoint; rate limited (5 attempts/min).

---

## 📊 2. `/` — Executive Overview Dashboard
- **Purpose**: High-level SOC situational awareness dashboard summarizing platform metrics.
- **Data Source**: `analyticsApi.getOverviewMetrics()`.
- **Main Actions**: View total alert counts, active incident graphs, agent activity feed, and system health status.
- **Relevant APIs**: `GET /api/v1/analytics/overview`.
- **Role & Security Restrictions**: Protected route; accessible to all authenticated roles (`READ_ONLY`, `SOC_ANALYST`, `INCIDENT_COMMANDER`, `ADMIN`).

---

## 🚨 3. `/alerts` — Telemetry & Triage Portal
- **Purpose**: Displays ingested security telemetry alerts with filter and triage controls.
- **Data Source**: `alertsApi.listAlerts()`.
- **Main Actions**: Search alerts by title/source, filter by severity (`LOW` to `CRITICAL`), trigger manual alert triage.
- **Relevant APIs**: `GET /api/v1/alerts`, `POST /api/v1/alerts`, `POST /api/v1/alerts/triage`.
- **Role & Security Restrictions**: Viewable by all roles; alert creation and triage require `SOC_ANALYST` or higher (`READ_ONLY` blocked).

---

## 🔥 4. `/incidents` — Incident Management Portal
- **Purpose**: Manages correlated security incidents and graph correlation evaluations.
- **Data Source**: `incidentsApi.listIncidents()`.
- **Main Actions**: Filter incidents by severity/status, trigger correlation engine run, view linked alerts.
- **Relevant APIs**: `GET /api/v1/incidents`, `POST /api/v1/incidents/correlate`.
- **Role & Security Restrictions**: Viewable by all roles; correlation trigger requires `SOC_ANALYST` or higher.

---

## 🔬 5. `/investigations` — Autonomous Investigation Console
- **Purpose**: Controls autonomous multi-stage investigation pipeline runs and views state context.
- **Data Source**: `investigationsApi.listInvestigations()`.
- **Main Actions**: Initiate autonomous investigation, view stage progress, inspect `InvestigationState`.
- **Relevant APIs**: `GET /api/v1/investigations`, `POST /api/v1/investigations`, `POST /api/v1/ai/pipeline/run`.
- **Role & Security Restrictions**: Pipeline execution requires `SOC_ANALYST` or higher.

---

## 🤖 6. `/agents` — Multi-Agent Collaboration Monitor
- **Purpose**: Displays live status, task distribution, and performance metrics for all 6 AI agents.
- **Data Source**: `aiApi.getAgentStatuses()`.
- **Main Actions**: Inspect individual agent execution logs, view agent tool capabilities, check latency metrics.
- **Relevant APIs**: `GET /api/v1/ai/agents/status`.
- **Role & Security Restrictions**: Protected route; accessible to all authenticated roles.

---

## 🌐 7. `/threat-intelligence` — IOC Reputation Center
- **Purpose**: Extracts, normalizes, and enriches Threat Intelligence indicators (IPs, hashes, domains).
- **Data Source**: `threatIntelApi.listIndicators()`.
- **Main Actions**: Search IOCs, view provider consensus ratings, inspect threat actor mappings.
- **Relevant APIs**: `GET /api/v1/threat-intel/indicators`, `POST /api/v1/threat-intel/lookup`.
- **Role & Security Restrictions**: Read-only lookup available to all authenticated users.

---

## 🎯 8. `/mitre` — MITRE ATT&CK Matrix Visualization
- **Purpose**: Visualizes attack techniques mapped across the 14 MITRE ATT&CK tactical columns.
- **Data Source**: `mitreApi.getMatrix()`.
- **Main Actions**: Filter matrix by active investigation, view technique execution details and mitigation advice.
- **Relevant APIs**: `GET /api/v1/mitre/matrix`.
- **Role & Security Restrictions**: Accessible to all authenticated users.

---

## 🛡️ 9. `/detections` — Detection Engineering Console
- **Purpose**: Manages YARA, Sigma, and Suricata detection rule candidate lifecycles.
- **Data Source**: `detectionsApi.listRules()`.
- **Main Actions**: Create rule candidates, validate syntax, run dry-run tests, approve candidate rules.
- **Relevant APIs**: `GET /api/v1/detections/rules`, `POST /api/v1/detections/rules`, `POST /api/v1/detections/rules/{id}/approve`.
- **Role & Security Restrictions**: Rule approval requires `INCIDENT_COMMANDER` or `ADMIN` role.

---

## 💼 10. `/cases` — SOC Case Workspace
- **Purpose**: Enterprise case management workspace for multi-analyst collaboration.
- **Data Source**: `casesApi.listCases()`.
- **Main Actions**: Create case, assign analysts, add markdown comments, link evidence/incidents.
- **Relevant APIs**: `GET /api/v1/cases`, `POST /api/v1/cases`, `POST /api/v1/cases/{id}/comments`.
- **Role & Security Restrictions**: Case mutations require `SOC_ANALYST` or higher.

---

## 🛑 11. `/approvals` — Governance Approval Center
- **Purpose**: Centralized human review portal for pending `CaseApproval` response authorization requests.
- **Data Source**: `approvalsApi.listApprovals()`.
- **Main Actions**: Review response justifications, click **APPROVE** or **REJECT**.
- **Relevant APIs**: `GET /api/v1/approvals`, `POST /api/v1/approvals/{id}/decide`.
- **Role & Security Restrictions**: Approval decisions require `INCIDENT_COMMANDER` or `ADMIN` role (`SOC_ANALYST` and `READ_ONLY` blocked).

---

## ⚡ 12. `/playbooks` — SOAR Response Automation Portal
- **Purpose**: Displays SOAR playbooks, step definitions, and mock execution logs.
- **Data Source**: `playbooksApi.listPlaybooks()`.
- **Main Actions**: View playbook steps, trigger playbook in `SAFE_MOCK_EXECUTION` mode (with valid approval).
- **Relevant APIs**: `GET /api/v1/playbooks`, `POST /api/v1/playbooks/execute`.
- **Role & Security Restrictions**: Requires `APPROVED` `CaseApproval` record and `INCIDENT_COMMANDER` role. Enforces `SAFE_MOCK_EXECUTION`.

---

## ⏱️ 13. `/timeline` — Chronological Incident Reconstruction
- **Purpose**: Renders interactive attack event chronologies and DFIR process trees.
- **Data Source**: `timelineApi.getEvents()`.
- **Main Actions**: Filter timeline by event category/severity, inspect parent-child process relationships.
- **Relevant APIs**: `GET /api/v1/timeline/events`.
- **Role & Security Restrictions**: Accessible to all authenticated users.

---

## 📈 14. `/analytics` — SOC Performance & SLA Metrics
- **Purpose**: Operational analytics covering Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), and alert volume trends.
- **Data Source**: `analyticsApi.getMetrics()`.
- **Main Actions**: Select metric timeframes (24h, 7d, 30d), export PDF reports.
- **Relevant APIs**: `GET /api/v1/analytics/metrics`.
- **Role & Security Restrictions**: Accessible to all authenticated users.

---

## 🏥 15. `/system-health` — Infrastructure Monitoring Console
- **Purpose**: Monitors health status, latencies, and connectivity across PostgreSQL, Redis, and Elasticsearch.
- **Data Source**: `healthApi.getSystemHealth()`.
- **Main Actions**: Inspect database connection pools, Redis ping latency, and Elasticsearch cluster health.
- **Relevant APIs**: `GET /api/v1/health/deps`.
- **Role & Security Restrictions**: Protected route; accessible to all authenticated users.

---

## 🧪 16. `/demo` — End-to-End Security Validation Portal
- **Purpose**: Interactive synthetic attack scenario execution workspace for SOC demonstrations and evaluator testing.
- **Data Source**: `demoApi.listScenarios()`, `demoApi.getScenarioResult()`.
- **Main Actions**: Select synthetic scenario (Credential Compromise, Ransomware, Data Exfiltration), toggle auto-approve gate, execute scenario run, inspect 20-point assertions, view structured report.
- **Relevant APIs**: `GET /api/v1/demo/scenarios`, `POST /api/v1/demo/run`, `GET /api/v1/demo/report/{id}`.
- **Role & Security Restrictions**: Displays prominent `SYNTHETIC SECURITY ENVIRONMENT` and `SAFE MOCK SOAR BOUNDARY` banners.
