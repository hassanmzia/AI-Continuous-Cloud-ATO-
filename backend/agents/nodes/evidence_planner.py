"""
Node 3: Evidence Planner Agent (Agentic RAG)

Iteratively decides what evidence is needed for each control and which
MCP tools can collect it. Uses Agentic RAG to adapt its plan based on
what's available, what's stale, and what's missing.

This is "Agentic RAG" because the agent:
1. Retrieves knowledge about evidence requirements
2. Checks what evidence already exists (freshness)
3. Decides which MCP tools to invoke
4. May iterate if initial evidence is insufficient
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)

# MCP tool recommendations per evidence type and provider
TOOL_RECOMMENDATIONS = {
    "config_snapshot": {
        "aws": "compliance_core.get_config_snapshot",
        "aws_gov": "compliance_core.get_config_snapshot",
        "azure": "compliance_core.get_config_snapshot",
        "azure_gov": "compliance_core.get_config_snapshot",
        "gcp": "compliance_core.get_config_snapshot",
        "gcp_gov": "compliance_core.get_config_snapshot",
    },
    "log_export": {
        "aws": "compliance_core.query_audit_logs",
        "aws_gov": "compliance_core.query_audit_logs",
        "azure": "compliance_core.query_audit_logs",
        "azure_gov": "compliance_core.query_audit_logs",
        "gcp": "compliance_core.query_audit_logs",
        "gcp_gov": "compliance_core.query_audit_logs",
    },
    "scan_report": {
        "aws": "stig_scap.run_scap_scan",
        "azure": "stig_scap.run_scap_scan",
        "gcp": "stig_scap.run_scap_scan",
    },
    "asset_inventory": {
        "aws": "compliance_core.get_asset_inventory",
        "aws_gov": "compliance_core.get_asset_inventory",
        "azure": "compliance_core.get_asset_inventory",
        "azure_gov": "compliance_core.get_asset_inventory",
        "gcp": "compliance_core.get_asset_inventory",
        "gcp_gov": "compliance_core.get_asset_inventory",
    },
}

# Freshness SLAs in days
FRESHNESS_SLA = {
    "config_snapshot": 1,
    "log_export": 7,
    "scan_report": 30,
    "asset_inventory": 7,
    "policy_doc": 365,
    "ckl": 30,
}


def evidence_planner_agent(state: ComplianceState) -> ComplianceState:
    """
    Plan evidence collection strategy for each control.

    Agentic RAG loop:
    1. For each control, determine required evidence types
    2. Check existing evidence freshness in the vector store
    3. Identify gaps — what needs to be (re-)collected
    4. Map gaps to MCP tools per provider
    5. Produce an evidence_plan that the Evidence Collector will execute
    """
    logger.info(f"[EvidencePlanner] Planning evidence for {len(state.control_map)} controls")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "evidence_planner_agent",
        "action": "plan_evidence",
        "input_summary": {"control_count": len(state.control_map)},
        "output_summary": {},
        "duration_ms": 0,
    }

    evidence_plan: Dict[str, Any] = {}
    total_collections_needed = 0

    # Check existing evidence freshness
    existing_evidence = _check_existing_evidence(state.scope.system_id)

    for key, ctrl in state.control_map.items():
        control_id = ctrl.get("control_id", "")
        required_types = ctrl.get("required_evidence_types", ["config_snapshot"])

        plan_entry = {
            "control_id": control_id,
            "evidence_types": [],
            "sources": [],
            "existing_fresh": [],
            "needs_collection": [],
        }

        for ev_type in required_types:
            freshness_ok = _is_evidence_fresh(
                existing_evidence, control_id, ev_type
            )

            if freshness_ok:
                plan_entry["existing_fresh"].append(ev_type)
            else:
                plan_entry["needs_collection"].append(ev_type)
                total_collections_needed += 1

                # Map to MCP tools per provider
                for provider in state.scope.providers:
                    tool = TOOL_RECOMMENDATIONS.get(ev_type, {}).get(provider)
                    if tool:
                        plan_entry["sources"].append({
                            "evidence_type": ev_type,
                            "provider": provider,
                            "mcp_tool": tool,
                            "freshness_sla_days": FRESHNESS_SLA.get(ev_type, 30),
                        })

            plan_entry["evidence_types"].append(ev_type)

        evidence_plan[control_id] = plan_entry

    # Always include asset inventory as baseline
    for provider in state.scope.providers:
        inv_key = f"__inventory_{provider}"
        if inv_key not in evidence_plan:
            evidence_plan[inv_key] = {
                "control_id": "__asset_inventory",
                "evidence_types": ["asset_inventory"],
                "sources": [{
                    "evidence_type": "asset_inventory",
                    "provider": provider,
                    "mcp_tool": "compliance_core.get_asset_inventory",
                    "freshness_sla_days": 7,
                }],
                "existing_fresh": [],
                "needs_collection": ["asset_inventory"],
            }

    state.evidence_plan = evidence_plan

    trace_entry["output_summary"] = {
        "controls_planned": len(evidence_plan),
        "collections_needed": total_collections_needed,
        "providers": state.scope.providers,
    }
    state.agent_trace.append(trace_entry)

    logger.info(
        f"[EvidencePlanner] Plan complete: {len(evidence_plan)} entries, "
        f"{total_collections_needed} collections needed"
    )
    return state


def _check_existing_evidence(system_id: str) -> Dict[str, Any]:
    """Check what evidence already exists and its freshness."""
    try:
        from core.models import EvidenceArtifact

        artifacts = EvidenceArtifact.objects.filter(
            system_id=system_id
        ).order_by("-collected_at")[:500]

        evidence_index = {}
        for art in artifacts:
            for ctrl_id in (art.control_ids or []):
                key = f"{ctrl_id}:{art.artifact_type}"
                if key not in evidence_index:
                    evidence_index[key] = {
                        "artifact_id": str(art.id),
                        "collected_at": art.collected_at.isoformat(),
                        "artifact_type": art.artifact_type,
                    }
        return evidence_index
    except Exception as e:
        logger.debug(f"Existing evidence check failed: {e}")
        return {}


def _is_evidence_fresh(
    existing: Dict[str, Any],
    control_id: str,
    evidence_type: str,
) -> bool:
    """Check if existing evidence is within freshness SLA."""
    key = f"{control_id}:{evidence_type}"
    entry = existing.get(key)
    if not entry:
        return False

    try:
        collected_at = datetime.fromisoformat(entry["collected_at"])
        sla_days = FRESHNESS_SLA.get(evidence_type, 30)
        age_days = (datetime.now(timezone.utc) - collected_at).days
        return age_days <= sla_days
    except (ValueError, KeyError):
        return False
