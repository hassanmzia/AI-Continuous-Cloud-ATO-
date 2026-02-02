# MCP Tool Schemas — Multi-Cloud Compliance

## Design Principles

1. **One canonical interface, multiple provider implementations** — Same tool contract across AWS/Azure/GCP
2. **`provider` field routes to the right implementation** — Gov variants differ in endpoints, not operations
3. **Every tool returns**: `provider`, `system_id`, `evidence_artifact_id`, `hash`, `timestamp`
4. **MCP Router enforces**: allowlisted APIs, least-privilege credentials, rate limits, approval gates
5. **Full audit trail**: Every tool call is logged with input/output hash for compliance

## Tool Organization

```mermaid
graph TD
    subgraph "compliance_core (8 tools)"
        A1[get_asset_inventory]
        A2[get_config_snapshot]
        A3[query_audit_logs]
        A4[evaluate_control_rule]
        A5[store_evidence_artifact]
        A6[create_poam_item]
        A7[create_ticket]
        A8[detect_drift]
    end

    subgraph "stig_scap (4 tools)"
        B1[ingest_ckl]
        B2[run_scap_scan]
        B3[map_stig_to_nist_controls]
        B4[get_stig_benchmark_info]
    end

    subgraph "ticketing (3 tools)"
        C1[create_ticket]
        C2[update_ticket]
        C3[query_tickets]
    end

    subgraph "cicd (3 tools)"
        D1[create_remediation_pr]
        D2[run_terraform_plan]
        D3[run_policy_check]
    end
```

## Provider Mapping

| Canonical Operation | AWS | Azure | GCP |
|-------------------|-----|-------|-----|
| Asset Inventory | AWS Config | Resource Graph | Cloud Asset Inventory |
| Config Snapshot | Config + IAM + EC2/S3/EKS | ARM + Policy + Resource Graph | Asset Inventory (RESOURCE) |
| Audit Logs | CloudTrail | Activity Logs + Entra | Cloud Logging (Audit) |
| Security Posture | Security Hub + GuardDuty | Defender for Cloud + Sentinel | Security Command Center |
| OS/STIG Posture | SSM Inventory/Compliance | Guest Configuration | OS Config |

## MCP Router Flow

```mermaid
sequenceDiagram
    participant Agent
    participant Router as MCP Router
    participant Policy as Policy Engine
    participant Provider as Cloud Provider
    participant Audit as Audit Log

    Agent->>Router: call(tool_name, params)
    Router->>Policy: validate_tool_allowed()
    Router->>Policy: validate_provider_allowed()
    Router->>Policy: check_rate_limit()

    alt Requires Approval
        Router->>Audit: log(approval_required)
        Router-->>Agent: MCPApprovalRequired
    else Allowed
        Router->>Provider: execute(params)
        Provider-->>Router: result
        Router->>Audit: log(call_id, hash, duration)
        Router-->>Agent: result
    end
```

## Schema Files

- `schemas/mcp/compliance_core.json` — 8 canonical compliance tools
- `schemas/mcp/stig_scap.json` — 4 STIG/SCAP tools
- `schemas/mcp/ticketing.json` — 3 ticketing tools
- `schemas/mcp/cicd.json` — 3 CI/CD and IaC tools
