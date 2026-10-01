# AegisAI XDR — Detection Engine & Rule Synthesis Specifications

This document outlines the architecture, parsers, rule formats, synthesis lifecycle, and human approval constraints of the Detection Engine in **AegisAI XDR**.

---

## 🔍 Supported Rule Formats & Parsers

Implemented in `backend/app/domains/detections/`:

1. **Sigma Rules**: Generic log detection patterns for process execution, command-line arguments, and Windows Event Logs (`RuleParser.parse_sigma()`).
2. **YARA Rules**: Binary and memory artifact signatures for file hashes, string patterns, and hex sequences (`RuleParser.parse_yara()`).
3. **Suricata Rules**: Network intrusion detection rules for malicious HTTP headers, DNS queries, and TLS SNI indicators (`RuleParser.parse_suricata()`).
4. **Custom Rules**: Platform-native JSON/YAML behavioral detection rules.

---

## 🔄 Detection Rule Synthesis Lifecycle

```
[Verified Attack Evidence] ──> [Candidate Synthesis] ──> [Rule Parser] ──> [Rule Validator]
                                                                                │
[Potential Activation] <── [Human Review] <── [Quality Analysis] <── [Dry-Run Testing] ┘
```

1. **Evidence Extraction**: `DetectionRuleGeneratorAgent` extracts verified process command lines, file hashes, and network indicators from `InvestigationState`.
2. **Candidate Rule Generation**: The agent formats a candidate rule specification with metadata and detection logic.
3. **Parsing (`RuleParser`)**: Validates YAML/YARA/Suricata syntax and extracts detection selectors.
4. **Validation (`RuleValidator`)**: Checks mandatory schema fields (title, author, severity, MITRE tactics/techniques).
5. **Dry-Run Testing (`RuleTester`)**: Executes the rule candidate against historical telemetry in Elasticsearch/PostgreSQL to test match fidelity.
6. **Quality Analysis**: Calculates quality scores based on match precision, false-positive probability, and performance footprint.
7. **Human Analyst Review**: Synthesized rules are stored strictly in `CANDIDATE` status. A human SOC analyst must review and approve the candidate rule.
8. **Potential Activation**: Approved rules transition to `ACTIVE` status for deployment.

---

## 🛑 Security Constraint: No Automated Rule Deployment

> 🔒 **Critical Invariant**: Detection rules synthesized by `DetectionRuleGeneratorAgent` are **never automatically deployed to production sensors**. Candidate rules remain safely isolated in `CANDIDATE` status until a human SOC analyst performs dry-run validation and grants explicit approval.

---

## 🧪 Verification in Unit Tests

The Detection Engine lifecycle is verified in `tests/unit/test_detection_engine.py` and `tests/unit/test_detection_rule_generator.py`:
- Syntax validation testing for valid and invalid Sigma/YARA rules.
- Duplicate detection check preventing redundant rule creation.
- Quality score calculation and status transition verification.
