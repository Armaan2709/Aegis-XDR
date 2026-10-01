# AegisAI XDR — AI Orchestrator Foundation Module

## Overview

The **AI Orchestrator Foundation Module** is the core multi-agent execution framework for AegisAI XDR. It allows specialized security AI agents (e.g. Threat Hunter, Malware Analyst, DFIR Investigator, Threat Intelligence Analyst, Detection Rule Generator, Incident Commander) to collaborate safely and deterministically on security investigations.

---

## Architectural Guarantees & Security Model

> [!IMPORTANT]
> **Strict Security Isolation & Zero External LLM Calls**:
> - **No Cloud API Keys or External LLM Calls**: Operates deterministically offline via `MockLLMProvider` abstractions.
> - **Safe Read-Only Tools Only**: Security tools execute controlled read-only queries (`QuerySIEMTool`, `QueryThreatIntelTool`, `QueryMitreTool`, `QueryEvidenceTool`). No shell execution, arbitrary Python execution, filesystem destruction, process termination, network changes, or firewall/EDR modifications are permitted.
> - **Playbook Boundary Protection**: `ExecutePlaybookTool` cannot execute destructive actions directly or bypass `CaseApproval` human governance. Playbook requests are submitted as simulated runs subject to Case Management supervisor review.

---

## Core Components Architecture

### 1. Agent Abstraction (`agents/`)
- **`BaseAgent`**: Abstract interface defining `name`, `description`, `capabilities`, `execute()`, `validate_input()`, and `health_check()`.
- **`AgentResult`**: Structured response DTO capturing findings, evidence, confidence scores, recommendations, execution time, and metadata.
- **`AgentRegistry`**: Manages registration, capability searches, duplicate checks, and agent health verification.

### 2. Shared Investigation State (`orchestrator/state.py`)
- **`InvestigationState`**: Fully serializable Pydantic v2 state container passed across workflow nodes. Includes `investigation_id`, `incident_id`, `case_id`, `alerts`, `evidence`, `timeline`, `mitre_mappings`, `threat_intelligence`, `detection_matches`, `agent_results`, `hypotheses`, `risk_score`, `confidence_score`, `recommendations`, `current_phase`, and `execution_metadata`.

### 3. Workflow Graph Engine (`orchestrator/graph.py`)
- **`WorkflowGraph`**: LangGraph-compatible DAG engine supporting step dependency resolution, topological ordering, cycle detection, and conditional branching.
- **`WorkflowExecution`**: Tracks run status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`), completed step IDs, and failed step IDs.

### 4. Deterministic Consensus Engine (`orchestrator/consensus.py`)
- **`ConsensusEngine`**: Aggregates `AgentResult` outputs without LLM calls. Calculates weighted confidence scores, composite risk scores, detects conflicting findings, and ranks actionable recommendations.

### 5. Memory Abstraction (`memory/`)
- **`BaseMemoryStore`**: Abstract interface (`store`, `retrieve`, `search`, `delete`).
- **`ShortTermMemory`**: Ephemeral in-memory execution scope cache.
- **`CaseMemory`**: Case-scoped memory store queryable across long-term investigation artifacts.

### 6. LLM Provider Abstraction (`models/`)
- **`BaseLLMProvider`**: Interface for textual completion generation.
- **`MockLLMProvider`**: Local, deterministic mock LLM provider.
- **`LLMProviderFactory`**: Factory resolving active providers (prepared for future Ollama, OpenAI-compatible, or Anthropic backends).

### 7. Versioned Prompt Registry (`prompts/`)
- **`PromptTemplate`**: Formattable prompt template entity with variable enforcement.
- **`PromptRegistry`**: Manages versioned prompt templates, active version selection, and activation state.

### 8. REST API Endpoints (`router.py`)
Mounted under `/api/v1/ai`:
- `GET /ai/agents`: List registered agents and capabilities.
- `GET /ai/tools`: List registered safe security tools.
- `GET /ai/models`: List registered LLM providers.
- `GET /ai/health`: AI Orchestration layer health status.
- `POST /ai/investigations/{investigation_id}/start`: Execute multi-agent investigation workflow.

---

## Future Specialized Agent Integration Strategy

The AI Orchestrator Foundation is designed to seamlessly integrate specialized AI agents in future sprints:
1. **Threat Hunter Agent**: Performs telemetry hunting across endpoint logs and network flows.
2. **Malware Analyst Agent**: Performs automated static/dynamic payload inspection.
3. **DFIR Investigator Agent**: Analyzes memory dumps, disk artifacts, and process trees.
4. **Threat Intelligence Analyst Agent**: Enriches IOCs and correlates threat actor TTPs.
5. **Detection Rule Generator Agent**: Synthesizes custom YARA/Sigma/Suricata rules.
6. **Incident Commander Agent**: Synthesizes agent consensus and generates executive debriefs.
