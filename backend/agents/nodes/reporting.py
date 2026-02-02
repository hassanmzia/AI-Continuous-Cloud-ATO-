"""
Node 10: Reporting Agent (RAG)

Generates compliance reports using RAG to produce human-readable narratives:
  - ConMon (Continuous Monitoring) summary
  - SSP delta suggestions
  - Executive compliance dashboard data
  - SAP/SAR evidence bundles
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)


def reporting_agent(state: ComplianceState) -> ComplianceState:
    """
    Generate compliance reports from assessment results.

    Uses RAG to produce context-aware report narratives:
    1. ConMon summary — monthly continuous monitoring report
    2. SSP delta — suggested updates to implementation statements
    3. Executive summary — high-level dashboard data
    4. SAR bundle — evidence package for assessment report
    """
    logger.info(f"[Reporting] Generating reports for run {state.run_id}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "reporting_agent",
        "action": "generate_reports",
        "input_summary": {
            "assessments": len(state.control_assessments),
            "poam_items": len(state.poam_items),
            "drift_events": len(state.drift_events),
        },
        "output_summary": {},
        "duration_ms": 0,
    }

    reports = {}

    # 1. ConMon Summary
    reports["conmon_summary"] = _generate_conmon_summary(state)

    # 2. SSP Delta
    reports["ssp_delta"] = _generate_ssp_delta(state)

    # 3. Executive Summary
    reports["executive_summary"] = _generate_executive_summary(state)

    # 4. SAR Evidence Bundle manifest
    reports["sar_bundle"] = _generate_sar_bundle(state)

    # 5. Control family breakdown
    reports["family_breakdown"] = _generate_family_breakdown(state)

    state.reports = reports

    trace_entry["output_summary"] = {
        "reports_generated": list(reports.keys()),
    }
    state.agent_trace.append(trace_entry)

    logger.info(f"[Reporting] Generated {len(reports)} reports")
    return state


def _generate_conmon_summary(state: ComplianceState) -> Dict[str, Any]:
    """Generate Continuous Monitoring summary report."""
    summary = state.summary or {}

    return {
        "report_type": "conmon_summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system_id": state.scope.system_id,
        "system_name": state.scope.system_name,
        "period": f"{datetime.now(timezone.utc).strftime('%Y-%m')}",
        "baseline": state.scope.baseline,
        "providers_assessed": state.scope.providers,
        "overall_compliance_score": state.overall_score,
        "control_summary": summary,
        "drift_summary": {
            "total_events": len(state.drift_events),
            "by_severity": _count_by_key(state.drift_events, "severity"),
            "unresolved": sum(1 for d in state.drift_events if not d.get("resolved", False)),
        },
        "stig_summary": {
            "total_findings": len(state.stig_findings),
            "open": sum(1 for f in state.stig_findings if f.get("status") == "Open"),
            "cat_i_open": sum(
                1 for f in state.stig_findings
                if f.get("status") == "Open" and f.get("severity") == "CAT_I"
            ),
        },
        "poam_summary": {
            "new_items": len(state.poam_items),
            "by_severity": _count_by_key(state.poam_items, "severity"),
        },
        "remediation_tickets": len(state.tickets),
        "evidence_freshness": {
            "total_artifacts": len(state.evidence_artifacts),
            "fresh": sum(1 for a in state.evidence_artifacts if not a.get("stub")),
        },
        "narrative": (
            f"Continuous Monitoring Report for {state.scope.system_name} ({state.scope.baseline}). "
            f"Overall compliance score: {state.overall_score or 0:.1f}%. "
            f"Assessed {summary.get('total_controls', 0)} controls across "
            f"{len(state.scope.providers)} cloud provider(s). "
            f"{summary.get('passed', 0)} passed, {summary.get('failed', 0)} failed, "
            f"{summary.get('partial', 0)} partial. "
            f"{len(state.drift_events)} drift event(s) detected. "
            f"{len(state.poam_items)} new POA&M item(s) created."
        ),
    }


def _generate_ssp_delta(state: ComplianceState) -> Dict[str, Any]:
    """Generate SSP delta — suggested updates to implementation statements."""
    deltas: List[Dict[str, Any]] = []

    for assessment in state.control_assessments:
        if assessment.get("contradictions"):
            deltas.append({
                "control_id": assessment["control_id"],
                "framework": assessment["framework"],
                "issue": "SSP narrative may not reflect current implementation",
                "contradictions": assessment["contradictions"],
                "suggested_action": "Review and update SSP implementation statement",
            })

        if assessment["status"] == "fail":
            deltas.append({
                "control_id": assessment["control_id"],
                "framework": assessment["framework"],
                "issue": f"Control {assessment['control_id']} is currently failing",
                "rationale": assessment.get("rationale", ""),
                "suggested_action": "Update SSP to reflect current state and remediation plan",
            })

    return {
        "report_type": "ssp_delta",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_deltas": len(deltas),
        "deltas": deltas,
    }


def _generate_executive_summary(state: ComplianceState) -> Dict[str, Any]:
    """Generate executive-level compliance summary."""
    summary = state.summary or {}

    # Determine overall posture
    score = state.overall_score or 0
    if score >= 90:
        posture = "Strong"
    elif score >= 70:
        posture = "Moderate"
    elif score >= 50:
        posture = "Needs Improvement"
    else:
        posture = "At Risk"

    return {
        "report_type": "executive_summary",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "system_name": state.scope.system_name,
        "compliance_posture": posture,
        "compliance_score": score,
        "key_metrics": {
            "controls_assessed": summary.get("total_controls", 0),
            "controls_passing": summary.get("passed", 0),
            "controls_failing": summary.get("failed", 0),
            "open_poam_items": len(state.poam_items),
            "drift_events": len(state.drift_events),
            "cat_i_stig_findings": sum(
                1 for f in state.stig_findings
                if f.get("status") == "Open" and f.get("severity") == "CAT_I"
            ),
        },
        "top_risks": _identify_top_risks(state),
        "trend": "N/A",  # In production: compare with previous runs
    }


def _generate_sar_bundle(state: ComplianceState) -> Dict[str, Any]:
    """Generate SAR (Security Assessment Report) evidence bundle manifest."""
    return {
        "report_type": "sar_bundle",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "run_id": state.run_id,
        "system_id": state.scope.system_id,
        "evidence_artifacts": [
            {
                "artifact_id": a.get("artifact_id", ""),
                "artifact_type": a.get("artifact_type", ""),
                "provider": a.get("provider", ""),
                "collected_at": a.get("collected_at", ""),
                "hash": a.get("hash", ""),
            }
            for a in state.evidence_artifacts
        ],
        "assessment_results": [
            {
                "control_id": a["control_id"],
                "framework": a["framework"],
                "status": a["status"],
                "confidence": a.get("confidence", 0),
            }
            for a in state.control_assessments
        ],
        "agent_trace_hash": "",  # In production: hash of full trace
    }


def _generate_family_breakdown(state: ComplianceState) -> Dict[str, Any]:
    """Generate per-control-family compliance breakdown."""
    families: Dict[str, Dict] = {}

    for assessment in state.control_assessments:
        ctrl_id = assessment.get("control_id", "")
        family = ctrl_id.split("-")[0] if "-" in ctrl_id else "Other"

        if family not in families:
            families[family] = {"total": 0, "pass": 0, "fail": 0, "partial": 0, "other": 0}

        families[family]["total"] += 1
        status = assessment["status"]
        if status == "pass":
            families[family]["pass"] += 1
        elif status == "fail":
            families[family]["fail"] += 1
        elif status == "partial":
            families[family]["partial"] += 1
        else:
            families[family]["other"] += 1

    # Add score per family
    for family, counts in families.items():
        total = counts["total"]
        counts["score"] = round((counts["pass"] / total * 100) if total > 0 else 0, 1)

    return {
        "report_type": "family_breakdown",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "families": families,
    }


def _identify_top_risks(state: ComplianceState) -> List[Dict[str, Any]]:
    """Identify top compliance risks for executive summary."""
    risks: List[Dict[str, Any]] = []

    # Critical/high failures
    for a in state.control_assessments:
        if a["status"] == "fail" and a.get("severity") in ("critical", "high"):
            risks.append({
                "type": "control_failure",
                "control_id": a["control_id"],
                "severity": a.get("severity", ""),
                "description": a.get("rationale", "")[:200],
            })

    # CAT I STIG findings
    for f in state.stig_findings:
        if f.get("status") == "Open" and f.get("severity") == "CAT_I":
            risks.append({
                "type": "stig_cat_i",
                "vuln_id": f.get("vuln_id", ""),
                "description": f.get("finding_details", "")[:200],
            })

    # Critical drift
    for d in state.drift_events:
        if d.get("severity") == "critical":
            risks.append({
                "type": "critical_drift",
                "resource_id": d.get("resource_id", ""),
                "description": f"Critical drift on {d.get('field', '')}",
            })

    return risks[:10]  # Top 10


def _count_by_key(items: List[Dict], key: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        val = item.get(key, "unknown")
        counts[val] = counts.get(val, 0) + 1
    return counts
