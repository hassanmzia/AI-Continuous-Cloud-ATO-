# A2A Protocol — Agent-to-Agent Communication

## Overview

Agents in the compliance mesh communicate via structured A2A messages. Each agent can be independently deployed as a service, enabling horizontal scaling and specialized resource allocation.

## Message Types

```mermaid
classDiagram
    class TaskRequest {
        +task_id: UUID
        +run_id: UUID
        +from_agent: string
        +to_agent: string
        +task_type: enum
        +payload: object
        +context: RunContext
        +priority: enum
        +deadline: datetime
        +correlation_id: string
    }

    class TaskResponse {
        +task_id: UUID
        +run_id: UUID
        +from_agent: string
        +to_agent: string
        +status: enum
        +result: object
        +artifacts: Artifact[]
        +errors: Error[]
        +metrics: Metrics
        +audit_trail: AuditEntry[]
    }

    class CommitteeReviewRequest {
        +review_id: UUID
        +control_ids: string[]
        +evidence_refs: string[]
        +assessor_agents: string[2+]
        +reconciliation_strategy: enum
    }

    class AgentHeartbeat {
        +agent_id: string
        +status: enum
        +current_task_id: string
        +capabilities: string[]
    }

    TaskRequest --> TaskResponse : produces
    CommitteeReviewRequest --> TaskResponse : produces
```

## Agent Registry

| Agent ID | Type | Capabilities |
|----------|------|-------------|
| `scope_resolver` | Utility | Scope resolution, RBAC enforcement |
| `control_mapping_agent` | RAG | Control mapping, framework crosswalk |
| `evidence_planner_agent` | Agentic RAG | Evidence planning, tool selection, freshness evaluation |
| `evidence_collector_agent` | MCP | Evidence collection, artifact storage |
| `drift_detection_agent` | MCP | Drift detection, change attribution, baseline comparison |
| `stig_posture_agent` | MCP | STIG assessment, SCAP scanning, CKL ingestion |
| `gap_analysis_agent` | Advanced RAG | Gap analysis, contradiction detection, sufficiency scoring |
| `remediation_agent` | MCP | POA&M creation, ticket creation, PR creation |
| `reporting_agent` | RAG | Report generation, SSP delta, ConMon summary |

## Communication Flow

```mermaid
flowchart LR
    subgraph Orchestrator
        O[LangGraph<br/>State Machine]
    end

    subgraph "Agent Mesh"
        A1[Scope Resolver]
        A2[Control Mapping]
        A3[Evidence Planner]
        A4[Evidence Collector]
        A5[Drift Detection]
        A6[STIG Posture]
        A7[Gap Analysis]
        A8[Remediation]
        A9[Reporting]
    end

    O -->|TaskRequest| A1
    A1 -->|TaskResponse| O

    O -->|TaskRequest| A2
    A2 -->|TaskResponse| O

    O -->|TaskRequest| A3
    A3 -->|TaskResponse| O

    O -->|TaskRequest| A4
    A4 -->|TaskResponse| O

    O -->|TaskRequest| A5
    A5 -->|TaskResponse| O

    O -->|TaskRequest| A6
    A6 -->|TaskResponse| O

    O -->|TaskRequest| A7
    A7 -->|TaskResponse| O
    A7 -.->|CommitteeReview| A7

    O -->|TaskRequest| A8
    A8 -->|TaskResponse| O

    O -->|TaskRequest| A9
    A9 -->|TaskResponse| O
```

## Task Types

- `control_mapping` — Map controls from frameworks to system boundary
- `evidence_planning` — Plan evidence collection strategy
- `evidence_collection` — Collect evidence via MCP tools
- `drift_detection` — Detect config drift across providers
- `stig_assessment` — STIG/SCAP assessment and mapping
- `gap_analysis` — Advanced gap analysis with sufficiency scoring
- `remediation` — Create POA&M, tickets, PRs
- `reporting` — Generate compliance reports
- `committee_review` — Dual-agent independent assessment for high-risk controls

## Schema File

See `schemas/a2a/agent_messages.json` for full JSON Schema definitions.
