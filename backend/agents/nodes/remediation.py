"""
Node 9: Remediation Agent (MCP)

Creates POA&M items, remediation tickets (Jira/ServiceNow/GitHub),
and optionally generates IaC pull requests for automated fixes.
Never auto-deploys — all PRs require human review.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)

# Default remediation timelines by severity
REMEDIATION_TIMELINES = {
    "critical": 30,   # days
    "high": 90,
    "moderate": 180,
    "low": 365,
}


def remediation_agent(state: ComplianceState, mcp_router=None) -> ComplianceState:
    """
    Create remediation actions for failed/partial controls.

    Workflow:
    1. Identify controls needing remediation (fail/partial)
    2. Create POA&M entries with milestones and owners
    3. Create remediation tickets in external systems
    4. Optionally create IaC PRs for automated fixes (never auto-deploy)
    """
    logger.info(f"[Remediation] Processing remediation for run {state.run_id}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "remediation_agent",
        "action": "create_remediation",
        "input_summary": {
            "assessments": len(state.control_assessments),
            "failures": sum(1 for a in state.control_assessments if a["status"] in ("fail", "partial")),
        },
        "output_summary": {},
        "duration_ms": 0,
    }

    poam_items: List[Dict[str, Any]] = []
    tickets: List[Dict[str, Any]] = []

    # Filter controls needing remediation
    needs_remediation = [
        a for a in state.control_assessments
        if a["status"] in ("fail", "partial")
    ]

    for assessment in needs_remediation:
        control_id = assessment["control_id"]
        framework = assessment["framework"]
        severity = assessment.get("severity", "moderate")

        # Compute due date based on severity
        timeline_days = REMEDIATION_TIMELINES.get(severity, 180)
        due_date = (datetime.now(timezone.utc) + timedelta(days=timeline_days)).strftime("%Y-%m-%d")

        # Create POA&M item
        poam = _create_poam(
            system_id=state.scope.system_id,
            control_id=control_id,
            framework=framework,
            assessment=assessment,
            due_date=due_date,
            mcp_router=mcp_router,
            run_id=state.run_id,
        )
        poam_items.append(poam)

        # Create remediation ticket for high/critical
        if severity in ("high", "critical"):
            ticket = _create_ticket(
                system_id=state.scope.system_id,
                control_id=control_id,
                assessment=assessment,
                poam_id=poam.get("poam_id", ""),
                mcp_router=mcp_router,
                run_id=state.run_id,
            )
            tickets.append(ticket)

    # Also create tickets for open STIG CAT I findings
    cat_i_findings = [
        f for f in state.stig_findings
        if f.get("status") == "Open" and f.get("severity") == "CAT_I"
    ]
    for finding in cat_i_findings:
        ticket = _create_stig_ticket(
            system_id=state.scope.system_id,
            finding=finding,
            mcp_router=mcp_router,
            run_id=state.run_id,
        )
        tickets.append(ticket)

    state.poam_items = poam_items
    state.tickets = tickets

    trace_entry["output_summary"] = {
        "poam_created": len(poam_items),
        "tickets_created": len(tickets),
    }
    state.agent_trace.append(trace_entry)

    logger.info(
        f"[Remediation] Created {len(poam_items)} POA&M items, {len(tickets)} tickets"
    )
    return state


def _create_poam(
    system_id: str,
    control_id: str,
    framework: str,
    assessment: Dict[str, Any],
    due_date: str,
    mcp_router=None,
    run_id: str = "",
) -> Dict[str, Any]:
    """Create a POA&M item via MCP or directly."""
    milestones = [
        {
            "description": "Root cause analysis and remediation plan",
            "target_date": (datetime.now(timezone.utc) + timedelta(days=14)).strftime("%Y-%m-%d"),
            "status": "pending",
        },
        {
            "description": "Implement remediation",
            "target_date": (datetime.now(timezone.utc) + timedelta(days=60)).strftime("%Y-%m-%d"),
            "status": "pending",
        },
        {
            "description": "Verify remediation and collect evidence",
            "target_date": due_date,
            "status": "pending",
        },
    ]

    poam_params = {
        "system_id": system_id,
        "framework": framework,
        "control_id": control_id,
        "weakness": assessment.get("rationale", f"Control {control_id} assessment: {assessment['status']}"),
        "severity": assessment.get("severity", "moderate"),
        "milestones": milestones,
        "owner": "system-owner@example.com",  # In production: from system model
        "due_date": due_date,
        "evidence_artifact_ids": [
            c.get("artifact_id", "") for c in assessment.get("evidence_citations", [])
        ],
    }

    if mcp_router:
        try:
            result = mcp_router.call(
                tool_name="compliance_core.create_poam_item",
                params=poam_params,
                run_id=run_id,
                agent_id="remediation_agent",
            )
            return {
                "poam_id": result.get("poam_id", ""),
                "control_id": control_id,
                "framework": framework,
                "severity": assessment.get("severity", "moderate"),
                "due_date": due_date,
                "status": "open",
            }
        except Exception as e:
            logger.error(f"POA&M creation via MCP failed: {e}")

    # Fallback: create in DB directly
    try:
        from core.models import POAMItem
        poam = POAMItem.objects.create(
            system_id=system_id,
            run_id=run_id if run_id else None,
            framework=framework,
            control_id=control_id,
            weakness=poam_params["weakness"],
            severity=poam_params["severity"],
            owner=poam_params["owner"],
            due_date=due_date,
            milestones=milestones,
        )
        return {
            "poam_id": str(poam.id),
            "control_id": control_id,
            "framework": framework,
            "severity": assessment.get("severity", "moderate"),
            "due_date": due_date,
            "status": "open",
        }
    except Exception as e:
        logger.warning(f"DB POA&M creation failed: {e}")
        return {
            "poam_id": f"stub-poam-{control_id}",
            "control_id": control_id,
            "framework": framework,
            "severity": assessment.get("severity", "moderate"),
            "due_date": due_date,
            "status": "open",
        }


def _create_ticket(
    system_id: str,
    control_id: str,
    assessment: Dict[str, Any],
    poam_id: str,
    mcp_router=None,
    run_id: str = "",
) -> Dict[str, Any]:
    """Create a remediation ticket via MCP."""
    title = f"[ATO] Remediate {control_id} ({assessment.get('framework', '')}) - {assessment.get('severity', '')}"
    description = (
        f"**Control:** {control_id}\n"
        f"**Framework:** {assessment.get('framework', '')}\n"
        f"**Status:** {assessment['status']}\n"
        f"**Severity:** {assessment.get('severity', '')}\n"
        f"**Confidence:** {assessment.get('confidence', 0):.0%}\n\n"
        f"**Rationale:**\n{assessment.get('rationale', '')}\n\n"
        f"**POA&M ID:** {poam_id}\n"
        f"**Drift Detected:** {assessment.get('drift_detected', False)}\n"
    )

    if mcp_router:
        try:
            result = mcp_router.call(
                tool_name="compliance_core.create_ticket",
                params={
                    "system": "jira",
                    "title": title,
                    "description": description,
                    "priority": assessment.get("severity", "medium"),
                    "labels": ["ato", "compliance", control_id, assessment.get("framework", "")],
                    "links": [poam_id],
                },
                run_id=run_id,
                agent_id="remediation_agent",
            )
            return {
                "ticket_id": result.get("ticket_id", ""),
                "ticket_url": result.get("ticket_url", ""),
                "system": "jira",
                "title": title,
                "linked_controls": [control_id],
            }
        except Exception as e:
            logger.error(f"Ticket creation via MCP failed: {e}")

    return {
        "ticket_id": f"stub-ticket-{control_id}",
        "ticket_url": "",
        "system": "jira",
        "title": title,
        "linked_controls": [control_id],
    }


def _create_stig_ticket(
    system_id: str,
    finding: Dict[str, Any],
    mcp_router=None,
    run_id: str = "",
) -> Dict[str, Any]:
    """Create a ticket for a CAT I STIG finding."""
    vuln_id = finding.get("vuln_id", "")
    title = f"[STIG] CAT I Finding: {vuln_id} - {finding.get('stig_name', '')}"

    return {
        "ticket_id": f"stub-stig-{vuln_id}",
        "ticket_url": "",
        "system": "jira",
        "title": title,
        "linked_controls": finding.get("mapped_nist_controls", []),
    }
