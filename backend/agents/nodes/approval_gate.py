"""
Node 8: Approval Gate (Human-in-the-Loop)

Policy-based gate that determines whether remediation actions require
human approval before execution. Creates approval requests in the DB
for the React console to display.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

from agents.state import ComplianceState

logger = logging.getLogger(__name__)


def approval_gate(state: ComplianceState) -> str:
    """
    Conditional edge: decide whether to route to approval or auto-remediate.

    Returns:
        "await_approval" — if human review is needed
        "auto_remediate" — if auto-remediation is permitted
    """
    if state.requires_approval:
        logger.info(
            f"[ApprovalGate] Approval required for run {state.run_id}: "
            f"{len(state.approval_reasons)} reason(s)"
        )
        return "await_approval"

    logger.info(f"[ApprovalGate] Auto-remediation permitted for run {state.run_id}")
    return "auto_remediate"


def await_approval_node(state: ComplianceState) -> ComplianceState:
    """
    Create approval requests and persist them for the UI.

    The workflow pauses here until a human reviewer approves/rejects.
    In production: uses LangGraph interrupt + webhook callback.
    """
    logger.info(f"[ApprovalGate] Creating approval requests for run {state.run_id}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "approval_gate",
        "action": "request_approval",
        "input_summary": {
            "reasons": state.approval_reasons,
            "failed_controls": [
                a["control_id"] for a in state.control_assessments
                if a["status"] == "fail"
            ],
        },
        "output_summary": {},
        "duration_ms": 0,
    }

    # Create approval requests in DB
    approval_requests = []
    try:
        from core.models import ApprovalRequest as ApprovalModel

        # Group failed controls by severity for batch approval
        critical_failures = [
            a for a in state.control_assessments
            if a["status"] == "fail" and a.get("severity") in ("high", "critical")
        ]

        if critical_failures:
            approval = ApprovalModel.objects.create(
                run_id=state.run_id,
                system_id=state.scope.system_id,
                action_type="remediation",
                action_payload={
                    "failed_controls": [
                        {
                            "control_id": a["control_id"],
                            "framework": a["framework"],
                            "severity": a.get("severity", ""),
                            "rationale": a.get("rationale", "")[:500],
                        }
                        for a in critical_failures
                    ],
                    "proposed_actions": ["create_poam", "create_tickets"],
                },
                affected_controls=[a["control_id"] for a in critical_failures],
                severity="high",
                requested_by_agent="gap_analysis_agent",
            )

            approval_requests.append({
                "approval_id": str(approval.id),
                "action_type": "remediation",
                "status": "pending",
                "affected_controls": [a["control_id"] for a in critical_failures],
            })

    except Exception as e:
        logger.warning(f"[ApprovalGate] DB persistence failed: {e} — using in-memory approval")
        approval_requests.append({
            "approval_id": f"approval-{state.run_id}",
            "action_type": "remediation",
            "status": "pending",
            "affected_controls": [
                a["control_id"] for a in state.control_assessments
                if a["status"] == "fail"
            ],
        })

    state.approvals = approval_requests
    state.status = "awaiting_approval"

    trace_entry["output_summary"] = {
        "approvals_created": len(approval_requests),
    }
    state.agent_trace.append(trace_entry)

    logger.info(f"[ApprovalGate] {len(approval_requests)} approval request(s) created")
    return state
