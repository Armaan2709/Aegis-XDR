# AegisAI XDR — Portfolio & Evaluator Showcase Screenshot Checklist

This checklist provides a guide for capturing screenshots and visuals of the **AegisAI XDR** platform for portfolio presentations, project documentation, academic reports, and GitHub showcases.

---

## 📷 16 Recommended Presentation Screenshots

### 1. Analyst Authentication Portal (`/login`)
- **What Should Be Visible**: Enterprise dark-mode login card, JWT security badge, username/password inputs.
- **Why It Matters**: Demonstrates professional design system and stateless JWT authentication entry point.
- **Suggested Caption**: *"AegisAI XDR Analyst Authentication Interface featuring JWT RBAC security."*

---

### 2. Executive Overview Dashboard (`/`)
- **What Should Be Visible**: Top KPI cards (Total Alerts, Active Incidents, Agent Count, Health Status), severity distribution chart, live alert stream.
- **Why It Matters**: Establishes high-level SOC situational awareness and real-time telemetry aggregation.
- **Suggested Caption**: *"Executive SOC Command Center Overview showing real-time threat metrics."*

---

### 3. Telemetry & Triage Portal (`/alerts`)
- **What Should Be Visible**: Filterable security alerts table with severity badges (`CRITICAL`, `HIGH`), source tags, and triage action buttons.
- **Why It Matters**: Displays alert normalization, priority sorting, and analyst triage controls.
- **Suggested Caption**: *"Telemetry Triage Portal displaying normalized alert streams and severity classification."*

---

### 4. Incident Management Workspace (`/incidents`)
- **What Should Be Visible**: Correlated incident cards, linked alert counts, risk score gauges, and Trigger Correlation button.
- **Why It Matters**: Proves automated alert grouping into unified incident graphs.
- **Suggested Caption**: *"Incident Management Portal highlighting automated graph threat correlation."*

---

### 5. Autonomous Investigation Console (`/investigations`)
- **What Should Be Visible**: Active investigation list, 11-stage pipeline progress bar, `InvestigationState` JSON preview.
- **Why It Matters**: Demonstrates autonomous multi-stage investigation scheduling and state tracking.
- **Suggested Caption**: *"Autonomous Investigation Console tracking multi-stage pipeline state."*

---

### 6. Multi-Agent Collaboration Monitor (`/agents`)
- **What Should Be Visible**: 6 agent status cards (ThreatHunter, DFIR, ThreatIntel, RuleGen, Commander, Orchestrator) with tool badges and latency metrics.
- **Why It Matters**: Showcases the specialized multi-agent AI cluster architecture.
- **Suggested Caption**: *"Multi-Agent Collaboration Monitor displaying live status across all 6 specialized agents."*

---

### 7. Threat Intelligence IOC Center (`/threat-intelligence`)
- **What Should Be Visible**: Extracted IOC list (IPs, domains, file hashes), provider consensus score gauges, and threat actor tags.
- **Why It Matters**: Highlights automated IOC normalization and multi-feed threat reputation scoring.
- **Suggested Caption**: *"Threat Intelligence Center showing normalized IOC reputation and provider consensus."*

---

### 8. Digital Forensics Console (`/dfir`)
- **What Should Be Visible**: Reconstructed process tree graph (`cmd.exe` → `powershell.exe`), SHA256 evidence hashes, and decoded command lines.
- **Why It Matters**: Proves read-only forensic analysis, process tree building, and obfuscation decoding.
- **Suggested Caption**: *"DFIR Console demonstrating parent-child process tree reconstruction."*

---

### 9. Detection Engineering Console (`/detections`)
- **What Should Be Visible**: Synthesized Sigma/YARA/Suricata candidate rules, syntax validator output, and `CANDIDATE` status badge.
- **Why It Matters**: Demonstrates automated rule synthesis while emphasizing that candidate rules require human review before activation.
- **Suggested Caption**: *"Detection Engineering Console showing synthesized Sigma rule candidate in CANDIDATE status."*

---

### 10. Incident Commander Synthesis (`/incidents/synthesis`)
- **What Should Be Visible**: Executive investigation report summary, aggregated risk score (`88.5 / 100`), and proposed response plan.
- **Why It Matters**: Demonstrates senior AI synthesis of multi-agent findings into executive reports.
- **Suggested Caption**: *"Incident Commander Synthesis displaying executive summary and recommended response plan."*

---

### 11. Governance Approval Center (`/approvals`)
- **What Should Be Visible**: Pending `CaseApproval` records, action justification text, and **APPROVE** / **REJECT** decision buttons.
- **Why It Matters**: Proves the non-bypassable human-in-the-loop governance review gate.
- **Suggested Caption**: *"Governance Approval Center showcasing mandatory human review gate for response actions."*

---

### 12. SOAR Response Automation (`/playbooks`)
- **What Should Be Visible**: Playbook execution log step table with `SAFE_MOCK_EXECUTION` status badges.
- **Why It Matters**: Demonstrates safe response simulation without risking production infrastructure damage.
- **Suggested Caption**: *"SOAR Execution Console demonstrating safe response simulation under SAFE_MOCK_EXECUTION boundary."*

---

### 13. Chronological Attack Timeline (`/timeline`)
- **What Should Be Visible**: Interactive vertical timeline of security events tagged by attack phase (`INITIAL_ACCESS`, `EXECUTION`, etc.).
- **Why It Matters**: Shows chronological event reconstruction for post-incident forensic audits.
- **Suggested Caption**: *"Chronological Attack Timeline mapping events to MITRE ATT&CK tactical phases."*

---

### 14. SOC Analytics & Metrics (`/analytics`)
- **What Should Be Visible**: MTTD / MTTR trend charts, severity volume bar graphs, and SLA compliance indicators.
- **Why It Matters**: Proves operational performance tracking and response efficiency gains.
- **Suggested Caption**: *"SOC Performance Analytics tracking Mean Time to Detect (MTTD) and Respond (MTTR)."*

---

### 15. System Health & Infrastructure Monitoring (`/system-health`)
- **What Should Be Visible**: Latency monitors for PostgreSQL, Redis, and Elasticsearch, connection pool metrics, and liveness status.
- **Why It Matters**: Demonstrates enterprise production readiness and component health monitoring.
- **Suggested Caption**: *"Infrastructure Monitoring Console showing health latencies for PostgreSQL, Redis, and Elasticsearch."*

---

### 16. End-to-End Synthetic Security Validation (`/demo`)
- **What Should Be Visible**: Synthetic Isolation banners, scenario cards (`Credential Compromise`, `Ransomware`, `Exfiltration`), 11-stage progress tracker, and 20-point assertion checklist (`20/20 Passed`).
- **Why It Matters**: Serves as the primary evaluator demonstration portal proving end-to-end system correctness.
- **Suggested Caption**: *"End-to-End Security Validation Portal executing synthetic scenarios with 20/20 assertion verification."*
