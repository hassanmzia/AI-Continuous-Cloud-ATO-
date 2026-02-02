"""
ComplianceState — Central state model for the LangGraph compliance workflow.

This dataclass flows through all agent nodes, accumulating:
  - Scope (system, providers, baseline, frameworks)
  - Control mappings (RAG output)
  - Evidence plan + collected artifacts
  - Drift events + STIG findings
  - Control assessments with confidence scores
  - POA&M items + remediation tickets
  - Approval gates
  - Reports
  - Full audit trail
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional

Provider = Literal["aws", "aws_gov", "azure", "azure_gov", "gcp", "gcp_gov"]
Framework = Literal["fedramp", "nist_800_53_r5", "rmf", "stig"]
BaselineLevel = Literal["fedramp_low", "fedramp_mod", "fedramp_high", "custom"]


@dataclass
class RunScope:
    """Defines the boundary and parameters for a compliance run."""
    system_id: str = ""
    system_name: str = ""
    providers: List[str] = field(default_factory=list)
    environment: str = "production"
    boundary: Dict[str, Any] = field(default_factory=dict)
    baseline: str = "fedramp_mod"
    frameworks: List[str] = field(default_factory=lambda: ["fedramp", "nist_800_53_r5", "rmf", "stig"])


@dataclass
class ComplianceState:
    """
    Central state flowing through the LangGraph compliance workflow.

    Each agent node reads from and writes to specific fields.
    The full state is persisted per run for audit and resumability.
    """

    # --- Run metadata ---
    run_id: str = ""
    scope: RunScope = field(default_factory=RunScope)
    question: str = ""
    started_at: str = ""
    status: str = "pending"

    # --- Control Mapping Agent outputs (RAG) ---
    control_map: Dict[str, Any] = field(default_factory=dict)
    # Structure: { control_id: { title, family, owners, implementation_statements,
    #              required_evidence_types, frequencies, cross_mappings } }

    # --- Evidence Planner Agent outputs (Agentic RAG) ---
    evidence_plan: Dict[str, Any] = field(default_factory=dict)
    # Structure: { control_id: { evidence_types, sources, mcp_tools, freshness_sla } }

    # --- Evidence Collector outputs (MCP) ---
    evidence_artifacts: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { artifact_id, artifact_type, provider, hash, storage_uri, control_ids, collected_at }

    # --- Drift Detection Agent outputs (MCP) ---
    drift_events: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { resource_id, field, baseline_value, current_value, changed_by, severity, affected_controls }

    # --- STIG Posture Agent outputs (MCP) ---
    stig_findings: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { vuln_id, rule_id, severity, status, mapped_nist_controls, asset_id }

    # --- Gap Analysis Agent outputs (Advanced Agentic RAG) ---
    control_assessments: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { control_id, framework, status, confidence, rationale, evidence_citations,
    #         sufficiency_score, contradictions }

    # --- Remediation Agent outputs (MCP) ---
    poam_items: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { poam_id, control_id, weakness, severity, milestones, owner, due_date }

    tickets: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { ticket_id, ticket_url, system, title, linked_controls }

    # --- Approval Gate ---
    requires_approval: bool = False
    approval_reasons: List[str] = field(default_factory=list)
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { approval_id, action_type, status, reviewed_by, reviewed_at }

    # --- Reporting Agent outputs (RAG) ---
    reports: Dict[str, Any] = field(default_factory=dict)
    # Keys: conmon_summary, ssp_delta, executive_summary, sar_bundle

    # --- Audit Trail ---
    agent_trace: List[Dict[str, Any]] = field(default_factory=list)
    # Each: { timestamp, agent_id, action, input_summary, output_summary, duration_ms }

    # --- Summary ---
    overall_score: Optional[float] = None  # 0-100 compliance score
    summary: Dict[str, Any] = field(default_factory=dict)
    # { total_controls, passed, failed, partial, not_applicable, manual_review }

    errors: List[Dict[str, Any]] = field(default_factory=list)
