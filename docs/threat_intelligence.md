# AegisAI XDR — Threat Intelligence & IOC Enrichment Specifications

This document specifies the Threat Intelligence domain, IOC extraction engines, reputation scoring, provider consensus algorithms, and attribution constraints in **AegisAI XDR**.

---

## 🎯 1. IOC Extraction & Normalization

Implemented in `backend/app/domains/threat_intelligence/`:

- **Regex & Pattern Extraction**: Automatically parses security alerts and evidence payloads for:
  - IPv4 / IPv6 addresses (`extract_ips()`)
  - Domain Names & FQDNs (`extract_domains()`)
  - File Hashes (MD5, SHA1, SHA256) (`extract_hashes()`)
  - URLs & URI parameters (`extract_urls()`)
- **IOC Normalization**: Converts all domains/urls to lower case, defangs malicious URLs (e.g. `hxxp[:]//`), and dedupes indicators.

---

## 📊 2. Reputation Lookups & Provider Consensus

Implemented in `ThreatIntelAnalystAgent` and threat intel services:

- **Enrichment Connectors**: Integrates with VirusTotal, MISP, AbuseIPDB, and AlienVault OTX feeds.
- **Provider Consensus Engine**:
  $$\text{Consensus Score} = \frac{\sum_{i=1}^{N} w_i \cdot R_i}{\sum_{i=1}^{N} w_i}$$
  where $w_i$ represents provider reliability weight and $R_i$ represents returned maliciousness rating (0.0 to 1.0).
- **Confidence Rating**: Computes overall confidence score based on provider count and indicator age.

---

## 🌐 3. Infrastructure Relationships & Threat Clustering

- **Infrastructure Linkage**: Maps IOCs to autonomous system numbers (ASNs), hosting providers, TLS certificate fingerprints, and dynamic DNS infrastructure.
- **Threat Clustering**: Groups related IOCs into threat actor activity clusters (e.g. `APT29 / Cozy Bear` alignment patterns) based on shared C2 infrastructure.

---

## 🛑 4. Conservative Attribution & Evidence Distinctions

> ⚖️ **Attribution Boundary**: AegisAI XDR enforces a strict distinction between **Verified Evidence** (observed host/network artifacts) and **Attribution Hypotheses** (threat actor tagging). Threat actor mappings are explicitly tagged as `HYPOTHESIS` with confidence intervals, preventing unwarranted false-positive attribution.

---

## 🧪 Verification in Unit Tests

Threat Intelligence services are tested in `tests/unit/test_threat_intelligence.py` and `tests/unit/test_threat_intelligence_agent.py`:
- IOC extraction accuracy across complex alert payloads.
- Provider consensus calculation logic.
- Threat score computation and confidence rating validation.
