# AegisAI XDR — DFIR & Forensic Reconstruction Specifications

This document outlines the Digital Forensics and Incident Response (DFIR) domain capabilities, forensic evidence management, process tree reconstruction, and timeline analysis in **AegisAI XDR**.

---

## 🔍 1. Forensic Artifact Normalization

Implemented in `backend/app/domains/evidence/` and `DFIRInvestigatorAgent`:

- **Supported Artifact Types**:
  - Memory Dumps (`MEMORY_DUMP`)
  - Packet Captures (`PCAP`)
  - Disk / File System Artifacts (`LOG_FILE`, `MFT`, `REGISTRY`)
  - Process Execution Logs (`PROCESS_CREATION`)
- **Evidence Integrity Verification**: Computes SHA256 cryptographic hashes on evidence upload to ensure chain-of-custody preservation.

---

## 🌳 2. Process Tree & Command-Line Analysis

```
 [services.exe (PID 620)]
        │
        └──> [cmd.exe (PID 2104)]
                    │
                    └──> [powershell.exe -enc SQBFAFgA... (PID 4412)]
                                │
                                └──> [vssadmin.exe delete shadows /all (PID 5120)]
```

- **Process Tree Builder**: Connects Parent Process IDs (PPID) to Process IDs (PID) to reconstruct execution chains.
- **Obfuscation Detection**: Decodes Base64-encoded PowerShell arguments (`-enc`, `-EncodedCommand`) and flags obfuscated script invocations.

---

## ⏱️ 3. Timeline Reconstruction & Attack Phases

Implemented in `backend/app/domains/timeline/`:

- **Chronological Reconstruction**: Aggregates network events, process creations, registry edits, and user logins into a unified chronological sequence.
- **MITRE ATT&CK Phase Tagging**: Maps timeline events to tactical attack phases:
  - `INITIAL_ACCESS` → `EXECUTION` → `PRIVILEGE_ESCALATION` → `DEFENSE_EVASION` → `CREDENTIAL_ACCESS` → `LATERAL_MOVEMENT` → `EXFILTRATION` → `IMPACT`.

---

## 🛑 4. Read-Only Forensic Analysis Boundary

> 🔒 **Forensic Preservation Constraint**: All DFIR forensic analysis routines operate strictly read-only over uploaded evidence files. AegisAI XDR never modifies or alters raw evidence files or host forensic artifacts during timeline analysis.

---

## 🧪 Verification in Unit Tests

DFIR capabilities are verified in `tests/unit/test_dfir_investigator.py`, `tests/unit/test_evidence.py`, and `tests/unit/test_timeline.py`:
- Process tree parent-child linking correctness.
- Obfuscated command decoding logic.
- Evidence hash preservation and chain-of-custody tracking.
