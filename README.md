# AI Continuous Cloud ATO

**Multi-Cloud AI-Driven Continuous Authority to Operate (ATO) Platform**

A production-grade compliance automation platform that uses **Agentic RAG**, **MCP** (Model Context Protocol), **A2A** (Agent-to-Agent), and **LangGraph** orchestration to continuously monitor and enforce **FedRAMP**, **NIST 800-53 Rev 5**, **RMF**, and **DoD STIG** compliance across **AWS**, **Azure**, and **GCP** — including Government partitions.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
  - [Platform Architecture](#platform-architecture)
  - [Agent Pipeline](#10-agent-compliance-pipeline)
  - [RAG Tiers](#three-tier-rag-architecture)
  - [MCP (Model Context Protocol)](#mcp--model-context-protocol)
  - [A2A (Agent-to-Agent)](#a2a--agent-to-agent-protocol)
  - [Data Model](#data-model)
- [Multi-Cloud Support](#multi-cloud-support)
- [Frameworks Supported](#compliance-frameworks-supported)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Configuration](#configuration)
  - [Cloud Provider Credentials](#cloud-provider-credentials)
- [API Reference](#api-reference)
- [Frontend Pages](#frontend-pages)
- [MCP Tool Reference](#mcp-tool-reference)
- [ATO-Grade Guarantees](#ato-grade-security-guarantees)
- [Development](#development)
- [Deployment](#deployment)
- [Architecture Documentation](#architecture-documentation)
- [License](#license)

---

## Overview

Traditional ATO processes are manual, slow, and point-in-time. A full ATO package can take **6-18 months** to prepare, and by the time it's approved, the evidence is already stale.

**AI Continuous Cloud ATO** transforms this into a **continuous, automated process**:

- A compliance lead asks: _"Are we still FedRAMP compliant today?"_
- The platform runs a **10-agent AI pipeline** that automatically:
  1. Resolves the system boundary and applicable controls
  2. Maps controls across frameworks (NIST, FedRAMP, RMF, STIG)
  3. Plans and collects evidence from multi-cloud environments
  4. Detects configuration drift with attribution
  5. Analyzes gaps with multi-hop RAG and contradiction detection
  6. Routes high-severity findings to human approval
  7. Creates POA&M items, tickets, and optional remediation PRs
  8. Generates ConMon reports, SSP deltas, and SAR bundles

All with **full audit trail**, **SHA-256 evidence hashing**, and **human-in-the-loop approval gates** — meeting the rigor expected for an Authority to Operate.

---

## How It Works

```
                    "Are we still FedRAMP compliant today?"
                                    |
                                    v
    +----------------------------------------------------------+
    |                   LangGraph Orchestrator                  |
    |                  (State Machine + Guardrails)             |
    +----------------------------------------------------------+
         |        |        |        |        |        |
         v        v        v        v        v        v
    [Scope] → [Control] → [Evidence] → [Drift] → [Gap] → [Report]
    Resolver   Mapping     Planning    Detection  Analysis  Generation
                (RAG)    (Agentic    (MCP)     (Advanced   (RAG)
                          RAG)                  Agentic
                                                RAG)
                                    |
                                    v
                          MCP Router / Proxy
                     (Policy · Audit · Rate Limits)
                                    |
                    +-------+-------+-------+
                    v       v       v       v
                  AWS    Azure    GCP    STIG/SCAP
                 (+Gov)  (+Gov)  (+Gov)  Ticketing
```

---

## Architecture

### Platform Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     PRESENTATION TIER                               │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  React 18 + TypeScript + Vite                                │  │
│  │  Dashboard | Cloud Accounts | Controls | Evidence | Drift    │  │
│  │  Approvals | Reports                                         │  │
│  └──────────────────────────┬────────────────────────────────────┘  │
│                             │ REST API + WebSocket                   │
├─────────────────────────────┼───────────────────────────────────────┤
│                     API & ORCHESTRATION TIER                        │
│  ┌──────────────┐  ┌────────────────┐  ┌──────────────────────┐    │
│  │ Django 5     │  │ Celery + Redis │  │ LangGraph            │    │
│  │ DRF API      │──│ Task Queue     │──│ Orchestrator         │    │
│  │ OpenAPI Docs │  │ Async Runs     │  │ State Machine        │    │
│  └──────────────┘  └────────────────┘  │ Conditional Edges    │    │
│                                         │ Approval Gates       │    │
│                                         └──────────┬───────────┘    │
├────────────────────────────────────────────────────┼────────────────┤
│                     AGENT MESH (A2A Protocol)       │               │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐           │
│  │ Scope  │→│Control │→│Evidence│→│Evidence│→│ Drift  │           │
│  │Resolver│ │Mapping │ │Planner │ │Collect.│ │Detect. │           │
│  └────────┘ └─(RAG)──┘ └(Agent.)┘ └─(MCP)─┘ └─(MCP)─┘           │
│       ↓                                                             │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐           │
│  │ STIG   │→│  Gap   │→│Approval│→│Remed.  │→│Report. │           │
│  │Posture │ │Analysis│ │ Gate   │ │ Agent  │ │ Agent  │           │
│  └─(MCP)─┘ └(Adv.RAG)┘ └(Human)┘ └─(MCP)─┘ └─(RAG)─┘           │
├─────────────────────────────────────────────────────────────────────┤
│                     MCP ROUTER / PROXY                              │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │  Policy Engine | Rate Limiting | Allowlists | mTLS           │  │
│  │  SHA-256 Hashing | Full Audit Trail | Approval Gates         │  │
│  └──────────┬──────────┬──────────┬──────────┬─────────────────┘  │
│             │          │          │          │                      │
├─────────────┼──────────┼──────────┼──────────┼─────────────────────┤
│             v          v          v          v                      │
│  ┌──────────┐ ┌────────┐ ┌───────┐ ┌──────────┐ ┌──────────┐      │
│  │AWS + Gov │ │Azure   │ │GCP    │ │STIG/SCAP │ │Ticketing │      │
│  │Config    │ │+ Gov   │ │+ Gov  │ │OpenSCAP  │ │Jira      │      │
│  │CloudTrail│ │Defender│ │Asset  │ │CKL/XCCDF │ │ServiceNow│      │
│  │SecHub    │ │Policy  │ │SCC    │ │CCI Cross.│ │GitHub    │      │
│  │IAM, SSM  │ │Entra   │ │Logging│ │Benchmarks│ │          │      │
│  └──────────┘ └────────┘ └───────┘ └──────────┘ └──────────┘      │
├─────────────────────────────────────────────────────────────────────┤
│                     DATA TIER                                       │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌────────────┐  │
│  │ PostgreSQL   │ │ Vector Store │ │ Evidence   │ │ Redis      │  │
│  │ + pgvector   │ │ pgvector /   │ │ Vault      │ │ Broker +   │  │
│  │ 13 tables    │ │ Chroma       │ │ MinIO/S3   │ │ Cache      │  │
│  │ UUID PKs     │ │ Embeddings   │ │ WORM+SHA256│ │            │  │
│  └──────────────┘ └──────────────┘ └────────────┘ └────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### 10-Agent Compliance Pipeline

The platform runs a **10-node LangGraph state machine**. Each node is a specialized agent with specific capabilities:

| # | Agent | Type | What It Does |
|---|-------|------|-------------|
| 1 | **Scope Resolver** | Utility | Validates system exists, resolves cloud providers, enforces RBAC, loads baseline configuration |
| 2 | **Control Mapping** | RAG | Maps applicable controls from NIST 800-53 / FedRAMP / RMF, cross-references STIG IDs via CCI crosswalk |
| 3 | **Evidence Planner** | Agentic RAG | Iteratively plans evidence collection: determines what evidence each control needs, checks freshness SLAs, selects MCP tools |
| 4 | **Evidence Collector** | MCP | Executes evidence collection across multi-cloud: config snapshots, audit logs, asset inventories. Stores artifacts with SHA-256 hashing |
| 5 | **Drift Detection** | MCP | Detects configuration drift (config, identity, network), attributes changes via audit logs, compares against baselines |
| 6 | **STIG Posture** | MCP | Ingests CKL/SCAP results, runs SCAP scans, maps STIG findings to NIST controls via CCI, categorizes by CAT I/II/III |
| 7 | **Gap Analysis** | Advanced Agentic RAG | Multi-hop retrieval across evidence, cross-encoder reranking, contradiction detection, evidence sufficiency scoring (0-1 confidence) |
| 8 | **Approval Gate** | Human-in-the-Loop | Routes high-severity findings (critical/high failures, CAT I STIGs, critical drift) to human approval queue |
| 9 | **Remediation** | MCP | Creates POA&M items with milestones, opens tickets (Jira/ServiceNow/GitHub), optionally creates IaC remediation PRs |
| 10 | **Reporting** | RAG | Generates ConMon summary, SSP delta report, executive dashboard data, SAR bundle with all evidence artifacts |

**Pipeline flow with conditional edges:**

```
Scope Resolver → Control Mapping → Evidence Planner → Evidence Collector
      → Drift Detection → STIG Posture → Gap Analysis
      → [Approval Gate] → Remediation → Reporting → Persist & Notify
                |
                ├── High severity → Human Review Queue (React UI)
                └── Low/moderate → Auto-remediate
```

### Three-Tier RAG Architecture

The platform implements three tiers of Retrieval Augmented Generation, each progressively more sophisticated:

| Tier | Description | Agents | Capabilities |
|------|------------|--------|-------------|
| **RAG** (Simple) | Standard retrieval + generation | Control Mapping, Reporting | Single-query vector search, control lookups, framework crosswalk, report narrative generation |
| **Agentic RAG** | Agent-driven iterative retrieval | Evidence Planner | Multi-step reasoning about what evidence to collect, tool selection, freshness SLA evaluation, re-planning when evidence is insufficient |
| **Advanced Agentic RAG** | Multi-hop with quality scoring | Gap Analysis | Multi-hop retrieval chains (up to 4 hops), cross-encoder reranking, contradiction detection across evidence, evidence sufficiency scoring with confidence intervals |

**RAG Data Sources:**
- NIST 800-53 Rev 5 control catalog (all families)
- FedRAMP baseline controls (Low/Moderate/High)
- DoD STIG benchmarks and rules
- System Security Plans (SSP) statements
- Policy documents and organizational procedures
- Historical evidence metadata and assessment results

**Indexing Pipeline:**
```
Source Documents → Chunking (type-specific sizes) → Metadata Extraction
    → Embedding (text-embedding-3-small, 1536 dims)
    → Vector Store (pgvector / Chroma / OpenSearch)
```

### MCP — Model Context Protocol

MCP provides **deterministic, auditable tool execution**. Every interaction with cloud APIs, STIG scanners, ticketing systems, and evidence storage goes through the MCP Router.

**Why MCP?**
- LLM function calling is non-deterministic — MCP provides canonical, versioned tool interfaces
- Every call is policy-checked, rate-limited, and audit-logged
- Provider-specific implementations behind a single canonical interface
- Approval gates for destructive or high-risk operations

**MCP Router Features:**
- Tool allowlists per agent (least privilege)
- Provider allowlists per system
- Rate limiting (configurable per tool)
- Approval gates for write operations
- SHA-256 output hashing for evidence integrity
- Full audit trail (input, output hash, duration, agent ID, timestamp)
- mTLS support for production deployments

**18 MCP Tools across 4 categories:**

| Category | Tools | Description |
|----------|-------|-------------|
| **compliance_core** (8) | `get_asset_inventory`, `get_config_snapshot`, `query_audit_logs`, `evaluate_control_rule`, `store_evidence_artifact`, `create_poam_item`, `create_ticket`, `detect_drift` | Core compliance operations across all cloud providers |
| **stig_scap** (4) | `ingest_ckl`, `run_scap_scan`, `map_stig_to_nist_controls`, `get_stig_benchmark_info` | DISA STIG and SCAP scanning operations |
| **ticketing** (3) | `create_ticket`, `update_ticket`, `query_tickets` | Jira, ServiceNow, GitHub Issues integration |
| **cicd** (3) | `create_remediation_pr`, `run_terraform_plan`, `run_policy_check` | CI/CD and Infrastructure as Code operations |

**Provider mapping — one interface, multiple implementations:**

| Canonical Operation | AWS | Azure | GCP |
|-------------------|-----|-------|-----|
| Asset Inventory | AWS Config | Resource Graph | Cloud Asset Inventory |
| Config Snapshot | Config + IAM + EC2/S3/EKS | ARM + Policy + Resource Graph | Asset Inventory (RESOURCE) |
| Audit Logs | CloudTrail | Activity Logs + Entra Audit | Cloud Logging (Admin Activity) |
| Security Posture | Security Hub + GuardDuty | Defender for Cloud + Sentinel | Security Command Center |
| OS/STIG Posture | SSM Inventory/Compliance | Guest Configuration | OS Config |

### A2A — Agent-to-Agent Protocol

Agents communicate via structured **A2A messages**, enabling:
- Independent deployment and horizontal scaling
- Typed contracts between agents
- Correlation tracking across the pipeline
- Committee review for high-risk decisions

**Message Types:**

| Type | Purpose |
|------|---------|
| `TaskRequest` | Orchestrator → Agent: assigns work with payload, context, priority, deadline |
| `TaskResponse` | Agent → Orchestrator: returns results, artifacts, errors, metrics, audit trail |
| `CommitteeReviewRequest` | Triggers dual-agent independent assessment for high-risk controls |
| `CommitteeReviewResponse` | Returns reconciled assessment or escalation recommendation |
| `AgentHeartbeat` | Health/status reporting from agents to orchestrator |

**Committee Review Flow (High-Risk Controls):**
```
Gap Analysis Agent
    ├── Assessor Agent 1 ──┐
    │                       ├── Reconciliation
    └── Assessor Agent 2 ──┘        │
                              ├── Agreement → Accept Assessment
                              └── Disagreement → Escalate to Human
```

### Data Model

The platform uses **13 core Django models** with UUID primary keys, timestamps, and full audit support:

| Group | Models | Description |
|-------|--------|-------------|
| **System Boundary** | `System`, `CloudAccount` | ATO boundaries with cloud provider accounts (AWS/Azure/GCP + Gov partitions) |
| **Controls** | `ControlCatalog`, `ControlMapping` | Framework control definitions and cross-framework mappings (NIST ↔ FedRAMP ↔ RMF ↔ STIG) |
| **Evidence** | `EvidenceArtifact`, `ComplianceRun`, `ControlAssessment` | Immutable evidence artifacts with SHA-256 hashes, compliance run tracking, per-control pass/fail assessments |
| **Findings** | `DriftEvent`, `StigFinding` | Configuration drift events with attribution, STIG/SCAP finding records with CAT severity |
| **Remediation** | `POAMItem`, `RemediationTicket` | Plan of Action & Milestones entries, external ticket references (Jira/ServiceNow/GitHub) |
| **Governance** | `ApprovalRequest`, `AuditLog` | Human-in-the-loop approval queue, immutable audit trail for all agent and MCP actions |

**Key enumerations:**
- **Provider**: `aws`, `aws_gov`, `azure`, `azure_gov`, `gcp`, `gcp_gov`
- **Framework**: `fedramp`, `nist_800_53_r5`, `rmf`, `stig`
- **Baseline**: `fedramp_low`, `fedramp_mod`, `fedramp_high`, `custom`
- **Severity**: `low`, `moderate`, `high`, `critical`
- **Assessment Status**: `pass`, `fail`, `partial`, `not_applicable`, `manual_review_required`

---

## Multi-Cloud Support

| Feature | AWS + GovCloud | Azure + Gov | GCP + Gov |
|---------|---------------|-------------|-----------|
| Asset Inventory | AWS Config | Resource Graph | Cloud Asset Inventory |
| Configuration Snapshots | Config, IAM, EC2, S3, EKS | ARM, Policy, Resource Graph | Asset Inventory (RESOURCE) |
| Audit Logs | CloudTrail | Activity Logs, Entra Audit | Cloud Logging (Admin Activity) |
| Security Posture | Security Hub, GuardDuty | Defender for Cloud, Sentinel | Security Command Center |
| Identity & Access | IAM Users/Roles/Policies | Entra ID, RBAC | IAM, Service Accounts |
| Network Security | VPC, Security Groups, NACLs | NSG, Azure Firewall | VPC, Firewall Rules |
| OS/STIG Compliance | SSM Inventory/Compliance | Guest Configuration | OS Config |
| Encryption | KMS, ACM | Key Vault, Disk Encryption | Cloud KMS |

**Government Partition Support:**
- AWS GovCloud (us-gov-west-1, us-gov-east-1) — separate IAM, dedicated partition
- Azure Government (usgovvirginia, usgovarizona) — separate Entra ID tenant
- GCP Government — configured via VPC Service Controls and Assured Workloads

---

## Compliance Frameworks Supported

| Framework | Coverage | Details |
|-----------|----------|---------|
| **FedRAMP** | Low / Moderate / High baselines | Full control catalog with baseline-specific parameter values |
| **NIST 800-53 Rev 5** | All control families (AC, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, RA, SA, SC, SI, SR) | Complete control definitions with assessment objectives |
| **RMF** | Full lifecycle (Categorize → Select → Implement → Assess → Authorize → Monitor) | Continuous monitoring phase automation |
| **DoD STIG** | CKL/SCAP ingestion, CCI crosswalk | Automated STIG-to-NIST control mapping via CCI (Control Correlation Identifier) |

**Cross-Framework Mapping:**
```
NIST 800-53 Control (e.g., AC-2)
    ↔ FedRAMP Control (AC-2 with FedRAMP parameters)
    ↔ RMF Control (AC-2 in RMF context)
    ↔ STIG Rule (via CCI-000001 → AC-2 mapping)
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | Django 5, Django REST Framework | REST API, ORM, admin, authentication |
| **Task Queue** | Celery + Redis | Async compliance run execution |
| **Orchestration** | LangGraph | State machine with conditional edges, approval gates |
| **RAG Framework** | LangChain | Document loading, chunking, embedding, retrieval chains |
| **Vector Store** | pgvector / Chroma / OpenSearch | Embedding storage and similarity search |
| **Embeddings** | OpenAI text-embedding-3-small (1536 dims) | Document and query embedding |
| **Reranking** | Cross-encoder (ms-marco-MiniLM) | Result reranking for Advanced Agentic RAG |
| **MCP** | Custom Python router | Policy enforcement, rate limiting, audit logging |
| **A2A** | JSON Schema contracts | Structured inter-agent communication |
| **Cloud SDKs** | boto3, azure-identity, azure-mgmt, google-cloud | Multi-cloud API access |
| **STIG** | OpenSCAP, CKL XML parsing | SCAP scanning, CKL ingestion, CCI crosswalk |
| **Frontend** | React 18, TypeScript, Vite | Single-page application |
| **UI Libraries** | TanStack Query, Recharts, React Router | Data fetching, charts, routing |
| **Database** | PostgreSQL 16 + pgvector | Relational data + vector embeddings |
| **Object Storage** | MinIO (S3-compatible) | Evidence vault with WORM support |
| **Cache/Broker** | Redis 7 | Celery broker + result backend |
| **Containerization** | Docker Compose | Local development environment |
| **API Docs** | drf-spectacular (OpenAPI 3.0) | Auto-generated Swagger/ReDoc |

---

## Project Structure

```
AI-Continuous-Cloud-ATO/
│
├── docs/
│   └── architecture/
│       ├── PLATFORM_ARCHITECTURE.md        # Platform overview with Mermaid diagrams
│       ├── AGENT_WORKFLOW.md               # Agent pipeline, RAG tiers, A2A sequences
│       ├── MCP_SCHEMAS.md                  # MCP tool organization and provider mapping
│       ├── A2A_PROTOCOL.md                 # Agent-to-agent message types and registry
│       ├── technical_architecture.drawio   # draw.io architecture diagram
│       └── AI_Continuous_ATO_Architecture.pptx  # PowerPoint slide deck
│
├── schemas/
│   ├── mcp/
│   │   ├── compliance_core.json            # 8 canonical compliance tools
│   │   ├── stig_scap.json                  # 4 STIG/SCAP tools
│   │   ├── ticketing.json                  # 3 ticketing tools
│   │   └── cicd.json                       # 3 CI/CD tools
│   └── a2a/
│       └── agent_messages.json             # A2A message type definitions
│
├── backend/
│   ├── config/
│   │   ├── settings.py                     # Django settings (DB, Celery, MCP, RAG, LLM)
│   │   ├── urls.py                         # URL routing with DRF Spectacular
│   │   ├── wsgi.py                         # WSGI entry point
│   │   └── celery.py                       # Celery app configuration
│   │
│   ├── core/
│   │   ├── models.py                       # 13 Django models (System, CloudAccount, etc.)
│   │   ├── serializers.py                  # DRF serializers for all models
│   │   ├── views.py                        # 14 ViewSets with filtering/search/pagination
│   │   ├── urls.py                         # DRF router registration
│   │   ├── admin.py                        # Django admin registration
│   │   ├── apps.py                         # Django app configuration
│   │   └── tasks.py                        # Celery tasks (run_compliance_check)
│   │
│   ├── mcp_tools/
│   │   ├── router.py                       # MCP Router (policy, rate limit, audit, hashing)
│   │   ├── providers/
│   │   │   ├── aws.py                      # AWS + GovCloud provider (boto3)
│   │   │   ├── azure.py                    # Azure + Gov provider (azure-mgmt)
│   │   │   └── gcp.py                      # GCP + Gov provider (google-cloud)
│   │   ├── evidence_vault.py               # MinIO/S3 evidence storage (SHA-256, WORM)
│   │   ├── stig.py                         # STIG/SCAP tools (CKL, SCAP, CCI crosswalk)
│   │   └── ticketing.py                    # Jira/ServiceNow/GitHub integration
│   │
│   ├── agents/
│   │   ├── state.py                        # ComplianceState + RunScope dataclasses
│   │   ├── orchestrator.py                 # LangGraph state graph + sequential fallback
│   │   ├── nodes/
│   │   │   ├── scope_resolver.py           # Node 1: System boundary + RBAC
│   │   │   ├── control_mapping.py          # Node 2: RAG control mapping
│   │   │   ├── evidence_planner.py         # Node 3: Agentic RAG evidence planning
│   │   │   ├── evidence_collector.py       # Node 4: MCP evidence collection
│   │   │   ├── drift_detection.py          # Node 5: MCP drift detection
│   │   │   ├── stig_posture.py             # Node 6: MCP STIG assessment
│   │   │   ├── gap_analysis.py             # Node 7: Advanced Agentic RAG gap analysis
│   │   │   ├── approval_gate.py            # Node 8: Human-in-the-loop gate
│   │   │   ├── remediation.py              # Node 9: MCP POA&M + tickets
│   │   │   └── reporting.py                # Node 10: RAG report generation
│   │   └── rag/
│   │       ├── indexing.py                 # Document indexing pipeline
│   │       ├── vector_store.py             # Vector store manager (pgvector/Chroma/OpenSearch)
│   │       └── retriever.py                # Hybrid retriever + reranking + sufficiency
│   │
│   ├── .env.example                        # Environment variable template
│   ├── requirements.txt                    # Python dependencies
│   ├── Dockerfile                          # Backend container image
│   └── manage.py                           # Django management script
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx                         # Main app with routing + sidebar navigation
│   │   ├── main.tsx                        # React entry point
│   │   ├── vite-env.d.ts                   # Vite type definitions
│   │   └── pages/
│   │       ├── Dashboard.tsx               # Compliance score, stats, recent runs
│   │       ├── CloudAccounts.tsx           # System + cloud account management
│   │       ├── ControlCockpit.tsx          # Control assessment table with filters
│   │       ├── EvidenceExplorer.tsx        # Evidence artifact browser
│   │       ├── DriftTimeline.tsx           # Drift event timeline with severity
│   │       ├── Approvals.tsx               # Human approval queue (approve/reject)
│   │       └── Reports.tsx                 # Report cards grid
│   │
│   ├── index.html                          # HTML entry point
│   ├── vite.config.ts                      # Vite dev server configuration
│   ├── tsconfig.json                       # TypeScript configuration
│   ├── package.json                        # Node dependencies
│   └── Dockerfile                          # Frontend container image
│
├── docker-compose.yml                      # Full dev stack (6 services)
├── Makefile                                # Development commands
├── .gitignore                              # Git ignore rules
└── README.md                               # This file
```

---

## Getting Started

### Prerequisites

- **Docker** and **Docker Compose** (v2.x)
- **Git**
- _(Optional)_ Cloud provider credentials for real assessments
- _(Optional)_ OpenAI API key for LLM-powered analysis

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/hassanmzia/AI-Continuous-Cloud-ATO-.git
cd AI-Continuous-Cloud-ATO-

# 2. Copy environment template and configure
cp backend/.env.example backend/.env
# Edit backend/.env with your settings (API keys, credentials, etc.)

# 3. Start all services
make build
make up

# 4. Check that everything is running
make logs
# You should see:
#   postgres   — "database system is ready to accept connections"
#   redis      — "Ready to accept connections"
#   minio      — "API: http://..."
#   backend    — "Watching for file changes with StatReloader"
#   celery     — "celery@... ready"
#   frontend   — "VITE ready in X ms"

# 5. Create an admin user
make createsuperuser

# 6. Access the platform
# Frontend:  http://localhost:13000
# API:       http://localhost:18000/api/
# API Docs:  http://localhost:18000/api/docs/
# Admin:     http://localhost:18000/admin/
# MinIO:     http://localhost:19001 (minioadmin/minioadmin)
```

### Configuration

All configuration is done via environment variables. Copy `backend/.env.example` to `backend/.env` and edit:

| Variable | Default | Description |
|----------|---------|-------------|
| `DJANGO_SECRET_KEY` | `change-me-...` | Django secret key (change in production) |
| `DEBUG` | `true` | Debug mode (set `false` in production) |
| `DB_HOST` | `postgres` | PostgreSQL hostname |
| `DB_NAME` | `ato_db` | Database name |
| `DB_USER` | `ato_user` | Database user |
| `DB_PASSWORD` | `ato_pass` | Database password |
| `CELERY_BROKER_URL` | `redis://redis:6379/0` | Celery broker URL |
| `EVIDENCE_VAULT_ENDPOINT` | `http://minio:9000` | MinIO/S3 endpoint |
| `VECTOR_DB_BACKEND` | `pgvector` | Vector store backend (`pgvector`, `chroma`, `opensearch`) |
| `LLM_PROVIDER` | `openai` | LLM provider (`openai`, `anthropic`) |
| `LLM_MODEL` | `gpt-4o` | LLM model name |
| `OPENAI_API_KEY` | — | OpenAI API key (required for RAG) |

### Cloud Provider Credentials

Each cloud provider uses its standard SDK credential chain:

**AWS:**
```bash
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJal...
AWS_DEFAULT_REGION=us-east-1
# GovCloud (separate credentials):
# AWS_GOVCLOUD_ACCESS_KEY_ID=...
# AWS_GOVCLOUD_SECRET_ACCESS_KEY=...
```

**Azure:**
```bash
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Azure Government:
# AZURE_AUTHORITY_HOST=https://login.microsoftonline.us
```

**GCP:**
```bash
GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-sa-key.json
# Mount the key file via docker-compose volumes:
# volumes:
#   - ./secrets/gcp-sa-key.json:/app/gcp-sa-key.json:ro
```

**Production recommendation:** Use IAM roles (AWS), Managed Identity (Azure), or Workload Identity (GCP) instead of static credentials.

---

## API Reference

All endpoints are available at `http://localhost:18000/api/`. Full OpenAPI documentation at `/api/docs/`.

| Endpoint | Methods | Description |
|----------|---------|-------------|
| `/api/systems/` | GET, POST | List/create ATO system boundaries |
| `/api/cloud-accounts/` | GET, POST, PUT, DELETE | Manage cloud provider accounts per system |
| `/api/controls/` | GET, POST | NIST/FedRAMP/STIG control catalog |
| `/api/control-mappings/` | GET, POST | Cross-framework control mappings |
| `/api/evidence/` | GET, POST | Evidence artifacts with integrity hashes |
| `/api/runs/` | GET | Compliance run history and results |
| `/api/runs/trigger/` | POST | **Trigger a new compliance check** |
| `/api/assessments/` | GET | Per-control assessment results |
| `/api/drift-events/` | GET | Configuration drift event timeline |
| `/api/stig-findings/` | GET | STIG/SCAP finding records |
| `/api/poam/` | GET, POST | Plan of Action & Milestones |
| `/api/tickets/` | GET, POST | Remediation ticket references |
| `/api/approvals/` | GET | Human approval queue |
| `/api/approvals/{id}/review/` | POST | Approve or reject a request |
| `/api/audit-logs/` | GET | Immutable audit trail |

**Triggering a compliance check:**

```bash
curl -X POST http://localhost:18000/api/runs/trigger/ \
  -H "Content-Type: application/json" \
  -d '{
    "system_id": "<uuid>",
    "question": "Are we still FedRAMP compliant today?",
    "providers": ["aws", "azure"],
    "baseline": "fedramp_mod"
  }'
```

---

## Frontend Pages

| Page | Route | Description |
|------|-------|-------------|
| **Dashboard** | `/` | Compliance score gauge, control status breakdown, recent compliance runs |
| **Cloud Accounts** | `/cloud-accounts` | Create systems, connect cloud accounts (AWS/Azure/GCP + Gov) |
| **Control Cockpit** | `/controls` | Filterable table of control assessments (pass/fail/partial) |
| **Evidence Explorer** | `/evidence` | Browse evidence artifacts with metadata, hashes, timestamps |
| **Drift Timeline** | `/drift` | Timeline view of drift events with severity color coding |
| **Approvals** | `/approvals` | Human approval queue — approve or reject high-severity actions |
| **Reports** | `/reports` | Report cards grid (ConMon, SSP Delta, Executive Summary, SAR) |

---

## MCP Tool Reference

### compliance_core (8 tools)

| Tool | Description | Cloud Providers |
|------|------------|----------------|
| `get_asset_inventory` | Enumerate all assets within system boundary | AWS Config, Azure Resource Graph, GCP Cloud Asset |
| `get_config_snapshot` | Fetch current configuration state for resource types | AWS Config/IAM, Azure ARM/Policy, GCP Asset (RESOURCE) |
| `query_audit_logs` | Query audit/activity logs for time range | CloudTrail, Activity Logs, Cloud Logging |
| `evaluate_control_rule` | Evaluate a control against collected evidence | Security Hub, Defender, SCC |
| `store_evidence_artifact` | Store artifact in evidence vault with SHA-256 hash | MinIO/S3 (WORM) |
| `create_poam_item` | Create Plan of Action & Milestones entry | Internal (PostgreSQL) |
| `create_ticket` | Create remediation ticket in external system | Jira, ServiceNow, GitHub |
| `detect_drift` | Compare current config against baseline | All providers |

### stig_scap (4 tools)

| Tool | Description |
|------|------------|
| `ingest_ckl` | Parse DISA STIG Viewer CKL XML files and extract findings |
| `run_scap_scan` | Execute OpenSCAP scan against benchmark |
| `map_stig_to_nist_controls` | Map STIG rule IDs to NIST 800-53 controls via CCI crosswalk |
| `get_stig_benchmark_info` | Retrieve STIG benchmark metadata and rules |

### ticketing (3 tools)

| Tool | Description |
|------|------------|
| `create_ticket` | Create ticket in Jira, ServiceNow, or GitHub |
| `update_ticket` | Update existing ticket status/fields |
| `query_tickets` | Search tickets by control, system, or status |

### cicd (3 tools)

| Tool | Description |
|------|------------|
| `create_remediation_pr` | Create a Git PR with IaC remediation code |
| `run_terraform_plan` | Execute Terraform plan for proposed changes |
| `run_policy_check` | Run OPA/Sentinel policy check against plan |

---

## ATO-Grade Security Guarantees

| # | Guarantee | Implementation |
|---|-----------|---------------|
| 1 | **Immutable Audit Trail** | Every MCP tool call logged with input parameters, output SHA-256 hash, timestamp, agent ID, duration, and correlation ID |
| 2 | **Evidence Integrity** | All evidence artifacts stored with SHA-256 hashing; MinIO configured for WORM (Write Once, Read Many) retention |
| 3 | **Human Approval Gates** | High-severity remediation (critical/high control failures, CAT I STIG findings, critical drift) requires explicit human approval |
| 4 | **Cross-Framework Mapping** | NIST 800-53 ↔ FedRAMP ↔ RMF ↔ STIG mapped via CCI (Control Correlation Identifier) crosswalk |
| 5 | **Multi-Cloud Parity** | Single canonical MCP interface across AWS/Azure/GCP; `provider` field routes to correct implementation |
| 6 | **Evidence Freshness SLAs** | Time-aware retrieval ensures evidence is within compliance windows; stale evidence triggers re-collection |

---

## Development

### Makefile Commands

```bash
make help              # Show all available commands
make up                # Start all services
make down              # Stop all services
make build             # Build all Docker images
make migrate           # Run Django migrations
make createsuperuser   # Create Django admin user
make shell             # Open Django Python shell
make test              # Run backend tests
make logs              # Tail all service logs
make logs-backend      # Tail backend logs only
make logs-celery       # Tail Celery worker logs
make psql              # Open PostgreSQL shell
make redis-cli         # Open Redis CLI
make api-docs          # Print API docs URL
```

### Adding a New MCP Tool

1. Define the tool schema in the appropriate `schemas/mcp/*.json` file
2. Add the canonical method to each provider in `backend/mcp_tools/providers/`
3. Register the tool in the MCP Router allowlist (`backend/mcp_tools/router.py`)
4. Add the tool call in the relevant agent node (`backend/agents/nodes/`)

### Adding a New Agent Node

1. Create the node module in `backend/agents/nodes/`
2. Define the node function signature: `def my_node(state: ComplianceState) -> ComplianceState`
3. Register the node in the LangGraph state graph (`backend/agents/orchestrator.py`)
4. Add conditional edges if needed
5. Update the A2A agent registry

---

## Deployment

### Development (Docker Compose)

The included `docker-compose.yml` runs all 6 services locally:

| Service | Container Port | Host Port | Description |
|---------|---------------|-----------|-------------|
| PostgreSQL | 5432 | 15432 | Database + pgvector |
| Redis | 6379 | 16379 | Celery broker + cache |
| MinIO | 9000/9001 | 19000/19001 | Evidence vault (S3-compatible) |
| Backend | 8000 | 18000 | Django API + admin |
| Celery Worker | — | — | Async task processing |
| Frontend | 3000 | 13000 | React dev server |

### Production

For production deployments, consider:

| Component | Recommended Service |
|-----------|-------------------|
| Database | Amazon RDS / Azure Database for PostgreSQL / Cloud SQL (with pgvector extension) |
| Redis | Amazon ElastiCache / Azure Cache for Redis / Memorystore |
| Object Storage | Amazon S3 / Azure Blob Storage / GCS (with WORM/retention policies) |
| Container Orchestration | Amazon EKS / AKS / GKE with Helm charts |
| Authentication | IAM Roles (AWS) / Managed Identity (Azure) / Workload Identity (GCP) |
| Secrets | AWS Secrets Manager / Azure Key Vault / GCP Secret Manager |
| Monitoring | CloudWatch / Azure Monitor / Cloud Monitoring + Prometheus/Grafana |
| CI/CD | GitHub Actions / Azure DevOps / Cloud Build |

---

## Architecture Documentation

Detailed architecture documentation with Mermaid diagrams:

| Document | Description |
|----------|-------------|
| [Platform Architecture](docs/architecture/PLATFORM_ARCHITECTURE.md) | High-level platform overview, component table, ATO guarantees |
| [Agent Workflow](docs/architecture/AGENT_WORKFLOW.md) | 10-agent pipeline, RAG tiers, A2A sequences, approval gate rules |
| [MCP Schemas](docs/architecture/MCP_SCHEMAS.md) | Tool organization, provider mapping, MCP router flow |
| [A2A Protocol](docs/architecture/A2A_PROTOCOL.md) | Message types, agent registry, communication flow |
| [Technical Architecture (draw.io)](docs/architecture/technical_architecture.drawio) | Editable architecture diagram for draw.io |
| [Architecture Slides (PPTX)](docs/architecture/AI_Continuous_ATO_Architecture.pptx) | PowerPoint slide deck for stakeholder presentations |

---

## License

This project is provided as a reference architecture for multi-cloud continuous ATO compliance.
