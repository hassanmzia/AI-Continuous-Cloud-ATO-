# Agent Workflow — LangGraph Compliance Pipeline

## Workflow Diagram

```mermaid
flowchart TD
    A[Start: User Query or Scheduled Run] --> B[1. Scope Resolver<br/>System boundary · Providers · Baseline · RBAC]

    B --> C[2. Control Mapping Agent<br/><b>RAG</b><br/>NIST/FedRAMP/RMF + STIG crosswalk]

    C --> D[3. Evidence Planner Agent<br/><b>Agentic RAG</b><br/>Choose evidence types + MCP tools<br/>Check freshness SLAs]

    D --> E[4. Evidence Collector Agent<br/><b>MCP</b><br/>Multi-cloud config + logs + scans<br/>Store artifacts + hash]

    E --> F[5. Drift Detection Agent<br/><b>MCP</b><br/>Config drift · Identity drift · Network drift<br/>Attribution via audit logs]

    F --> G[6. STIG Posture Agent<br/><b>MCP</b><br/>CKL/SCAP ingestion<br/>STIG → NIST mapping via CCI]

    G --> H[7. Gap Analysis Agent<br/><b>Advanced Agentic RAG</b><br/>Multi-hop retrieval · Contradiction detection<br/>Evidence sufficiency scoring]

    H --> I{Approval Gate<br/>Policy-based}

    I -- Approval Required --> J[8a. Human Review Queue<br/>React approval UI]
    J --> K[9. Remediation Agent<br/><b>MCP</b><br/>POA&M + Tickets + Optional PR]

    I -- Auto-Remediate OK --> K

    K --> L[10. Reporting Agent<br/><b>RAG</b><br/>ConMon · SSP Delta · SAR Bundle<br/>Executive Summary]

    L --> M[11. Persist & Notify<br/>Postgres + Evidence Vault<br/>Slack/Email/SIEM]
```

## RAG Tiers

| Tier | Agent | What It Does |
|------|-------|-------------|
| **RAG** | Control Mapping, Reporting | Retrieves compliance knowledge (controls, STIGs, SSP, policies) for context-aware responses |
| **Agentic RAG** | Evidence Planner | Iteratively decides which evidence to collect, checks freshness, selects MCP tools |
| **Advanced Agentic RAG** | Gap Analysis | Multi-hop retrieval, cross-encoder reranking, contradiction detection, evidence sufficiency scoring |

## Agent Communication (A2A)

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant CM as Control Mapping
    participant EP as Evidence Planner
    participant EC as Evidence Collector
    participant GA as Gap Analysis
    participant RA as Remediation Agent

    O->>CM: TaskRequest(control_mapping)
    CM-->>O: TaskResponse(control_map)

    O->>EP: TaskRequest(evidence_planning, control_map)
    EP-->>O: TaskResponse(evidence_plan)

    O->>EC: TaskRequest(evidence_collection, plan)
    EC-->>O: TaskResponse(artifacts[])

    O->>GA: TaskRequest(gap_analysis, artifacts)
    GA-->>O: TaskResponse(assessments, requires_approval)

    Note over O: Conditional: approval gate

    O->>RA: TaskRequest(remediation, assessments)
    RA-->>O: TaskResponse(poam_items, tickets)
```

## Committee Review (High-Risk Controls)

For high-risk controls, two agents independently assess and reconcile:

```mermaid
flowchart LR
    GA[Gap Analysis Agent] --> A1[Assessor Agent 1]
    GA --> A2[Assessor Agent 2]
    A1 --> R[Reconciliation]
    A2 --> R
    R --> |Agreement| PASS[Accept Assessment]
    R --> |Disagreement| ESC[Escalate to Human]
```

## Approval Gate Rules

| Condition | Action |
|-----------|--------|
| Any control fails with `severity: critical/high` | Route to human approval |
| CAT I STIG finding open | Route to human approval |
| Critical drift detected | Route to human approval |
| All assessments pass or low/moderate severity | Auto-remediate (create POA&M + tickets) |
