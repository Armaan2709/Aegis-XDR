# AegisAI XDR — Enterprise Threat Intelligence Engine

The **Threat Intelligence Engine** manages Indicators of Compromise (IOCs), offline multi-provider enrichment (VirusTotal, AbuseIPDB, AlienVault OTX, MISP, URLHaus, OpenPhish, GreyNoise, Shodan, CrowdSec), reputation scoring, caching, and feed ingestion.

## Core Capabilities

- **IOC Auto-Detection & Normalization**: Supports IPv4, IPv6, Domain, Hostname, URL, Email, SHA1, SHA256, MD5, Registry Keys, Mutex, Process, Certificate, User-Agent, and Filename.
- **Offline Multi-Provider Enrichment**: Abstracted interfaces executing deterministic mock providers without live network calls.
- **Consolidated Threat Reputation**: Maps aggregated provider scores to standard reputation levels (`MALICIOUS`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`, `BENIGN`, `UNKNOWN`).
- **Caching Layer**: Abstract `ThreatIntelCache` interface with TTL support, default in-memory implementation, prepared for Redis clustering.
- **IOC Relationships**: Directed relationship graphs between indicators (e.g. `DOMAIN` `RESOLVES_TO` `IPV4`).

## Module Architecture

```
backend/app/threat_intelligence/
├── __init__.py         # Package exports
├── models.py           # SQLAlchemy entities (IOC, ThreatFeed, ThreatEnrichment, IOCRelationship, etc.)
├── schemas.py          # Pydantic v2 validation contracts
├── repositories.py     # Database query layer
├── services.py         # Application service orchestrating lifecycle & lookups
├── router.py           # REST API endpoints (/api/v1/threat-intelligence)
├── providers.py        # Abstract provider interfaces & mock providers
├── ioc.py              # IOC validator, type detector, and normalizer
├── enrichment.py       # Multi-provider score aggregator & engine
├── cache.py            # Caching layer abstraction
└── README.md           # Domain documentation
```
