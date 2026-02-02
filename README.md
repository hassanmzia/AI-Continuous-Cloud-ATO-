# AI Continuous Cloud ATO

Multi-cloud AI-driven Continuous Authority to Operate (ATO) compliance operator. Uses **Agentic RAG**, **MCP** (Model Context Protocol), **A2A** (Agent-to-Agent), and **LangGraph** orchestration to continuously monitor FedRAMP / NIST 800-53 / RMF / DoD STIG compliance across AWS, Azure, and GCP (including Government partitions).

## What It Does

A compliance lead asks: *"Are we still FedRAMP compliant today?"*

The platform runs a 10-agent workflow that:

1. **Scope Resolver** — Resolves system boundary, providers, baseline, RBAC
2. **Control Mapping** (RAG) — Maps NIST/FedRAMP/RMF + STIG controls with crosswalk
3. **Evidence Planner** (Agentic RAG) — Plans evidence collection, checks freshness SLAs
4. **Evidence Collector** (MCP) — Collects config/logs/scans across multi-cloud
5. **Drift Detection** (MCP) — Detects config/identity/network drift with attribution
6. **STIG Posture** (MCP) — CKL/SCAP ingestion, STIG-to-NIST mapping via CCI
7. **Gap Analysis** (Advanced Agentic RAG) — Multi-hop retrieval, contradiction detection, sufficiency scoring
8. **Approval Gate** — Human-in-the-loop for high-severity remediation
9. **Remediation** (MCP) — Creates POA&M items, tickets, optional IaC PRs
10. **Reporting** (RAG) — ConMon summary, SSP delta, executive dashboard, SAR bundle

## Architecture

```
React/TS Console → Django API → LangGraph Orchestrator → Multi-Agent Mesh
                                        ↓
                               MCP Router/Proxy (mTLS, policy, audit)
                                        ↓
                    ┌──────────┬──────────┬──────────┬──────────┐
                    AWS/Gov    Azure/Gov   GCP/Gov   STIG/SCAP  Ticketing
```

See [docs/architecture/](docs/architecture/) for full Mermaid diagrams.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Django 5, Django REST Framework, Celery |
| Orchestration | LangGraph, LangChain |
| RAG | pgvector / Chroma, OpenAI embeddings, cross-encoder reranking |
| MCP | Custom router with policy enforcement + audit logging |
| A2A | Structured message contracts (TaskRequest/TaskResponse) |
| Cloud | boto3, azure-mgmt, google-cloud SDKs |
| STIG | OpenSCAP, CKL XML parsing, CCI crosswalk |
| Frontend | React 18, TypeScript, TanStack Query, Recharts |
| Infrastructure | Docker Compose, PostgreSQL + pgvector, Redis, MinIO |

## Quick Start

```bash
# Start all services
make up

# Run migrations
make migrate

# Create admin user
make createsuperuser

# View API docs
open http://localhost:8000/api/docs/

# View frontend
open http://localhost:3000
```

## Project Structure

```
├── docs/architecture/         # Architecture docs with Mermaid diagrams
├── schemas/
│   ├── mcp/                   # MCP tool JSON schemas (compliance_core, stig_scap, ticketing, cicd)
│   └── a2a/                   # A2A message contracts
├── backend/
│   ├── config/                # Django settings, URLs
│   ├── core/                  # Models, serializers, views (13 tables, full REST API)
│   ├── mcp_tools/             # MCP router + provider implementations (AWS/Azure/GCP + Gov)
│   │   ├── router.py          # Policy enforcement, rate limiting, audit logging
│   │   ├── providers/         # Cloud-specific implementations
│   │   ├── stig.py            # STIG/SCAP tools
│   │   ├── evidence_vault.py  # S3-compatible evidence storage with hashing
│   │   └── ticketing.py       # Jira/ServiceNow/GitHub
│   └── agents/
│       ├── state.py           # ComplianceState dataclass
│       ├── orchestrator.py    # LangGraph state graph + sequential fallback
│       ├── nodes/             # 10 agent nodes
│       └── rag/               # Indexing, vector store, hybrid retriever + reranking
├── frontend/src/
│   └── pages/                 # Dashboard, ControlCockpit, EvidenceExplorer,
│                              # DriftTimeline, Approvals, Reports
├── docker-compose.yml         # Postgres, Redis, MinIO, Backend, Celery, Frontend
└── Makefile                   # Dev commands
```

## Frameworks Supported

- **FedRAMP** (Low / Moderate / High baselines)
- **NIST 800-53 Rev 5** (full control catalog)
- **RMF** (Risk Management Framework lifecycle)
- **DoD STIG** (CKL/SCAP ingestion, CCI crosswalk to NIST)

## Cloud Providers

- AWS + AWS GovCloud
- Azure + Azure Government
- GCP + GCP Government
