"""
Node 6: STIG Posture Agent (MCP)

Ingests STIG Checklists (CKL) and SCAP scan results, then maps
findings to NIST 800-53 controls via CCI crosswalk. Critical for
DoD ATO environments.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)


def stig_posture_agent(state: ComplianceState, mcp_router=None) -> ComplianceState:
    """
    Assess STIG posture across system assets.

    Workflow:
    1. Identify assets that need STIG assessment
    2. Ingest existing CKLs from evidence vault
    3. Optionally trigger SCAP scans (where permitted)
    4. Map STIG findings to NIST/FedRAMP controls via CCI
    5. Record findings in state
    """
    logger.info(f"[StigPosture] Starting STIG assessment for system {state.scope.system_id}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "stig_posture_agent",
        "action": "assess_stig_posture",
        "input_summary": {"providers": state.scope.providers},
        "output_summary": {},
        "duration_ms": 0,
    }

    stig_findings: List[Dict[str, Any]] = []

    # Check if STIG framework is in scope
    if "stig" not in state.scope.frameworks and "rmf" not in state.scope.frameworks:
        logger.info("[StigPosture] STIG not in scope — skipping")
        trace_entry["output_summary"] = {"skipped": True, "reason": "STIG not in scope"}
        state.agent_trace.append(trace_entry)
        return state

    # Step 1: Look for existing CKL artifacts
    ckl_artifacts = [
        a for a in state.evidence_artifacts
        if a.get("artifact_type") in ("ckl", "scap_result")
    ]

    # Step 2: Ingest CKLs via MCP
    if mcp_router:
        for artifact in ckl_artifacts:
            try:
                result = mcp_router.call(
                    tool_name="stig_scap.ingest_ckl",
                    params={
                        "system_id": state.scope.system_id,
                        "asset_id": artifact.get("asset_id", "unknown"),
                        "ckl_uri": artifact.get("storage_uri", ""),
                        "environment": state.scope.environment,
                    },
                    run_id=state.run_id,
                    agent_id="stig_posture_agent",
                )

                for finding in result.get("findings", []):
                    finding["asset_id"] = artifact.get("asset_id", "unknown")
                    finding["stig_name"] = result.get("stig_name", "")
                    finding["stig_version"] = result.get("stig_version", "")
                    stig_findings.append(finding)

            except Exception as e:
                logger.error(f"[StigPosture] CKL ingestion failed: {e}")
                state.errors.append({
                    "agent": "stig_posture_agent",
                    "error": f"CKL ingestion failed: {str(e)[:200]}",
                })

        # Step 3: Map open findings to NIST controls
        open_findings = [f for f in stig_findings if f.get("status") == "Open"]
        if open_findings:
            rule_ids = [f.get("rule_id", "") for f in open_findings if f.get("rule_id")]
            try:
                mapping_result = mcp_router.call(
                    tool_name="stig_scap.map_stig_to_nist_controls",
                    params={
                        "stig_rule_ids": rule_ids,
                        "framework": "nist_800_53_r5",
                        "include_cci": True,
                    },
                    run_id=state.run_id,
                    agent_id="stig_posture_agent",
                )

                # Enrich findings with NIST control mappings
                mapping_index = {
                    m["stig_rule_id"]: m
                    for m in mapping_result.get("mappings", [])
                }
                for finding in stig_findings:
                    rule_id = finding.get("rule_id", "")
                    if rule_id in mapping_index:
                        finding["mapped_nist_controls"] = mapping_index[rule_id].get(
                            "nist_controls", []
                        )
                        finding["cci_ids"] = mapping_index[rule_id].get("cci_ids", [])

            except Exception as e:
                logger.error(f"[StigPosture] STIG-to-NIST mapping failed: {e}")
    else:
        # Stub mode
        stig_findings = _generate_stub_stig_findings()

    state.stig_findings = stig_findings

    # Compute summary
    summary = {
        "total": len(stig_findings),
        "open": sum(1 for f in stig_findings if f.get("status") == "Open"),
        "not_a_finding": sum(1 for f in stig_findings if f.get("status") == "Not_A_Finding"),
        "cat_i_open": sum(
            1 for f in stig_findings
            if f.get("status") == "Open" and f.get("severity") == "CAT_I"
        ),
        "cat_ii_open": sum(
            1 for f in stig_findings
            if f.get("status") == "Open" and f.get("severity") == "CAT_II"
        ),
    }

    trace_entry["output_summary"] = summary
    state.agent_trace.append(trace_entry)

    logger.info(f"[StigPosture] Assessment complete: {summary}")
    return state


def _generate_stub_stig_findings() -> List[Dict[str, Any]]:
    """Generate stub STIG findings for demo."""
    return [
        {
            "vuln_id": "V-254239",
            "rule_id": "SV-254239r848544_rule",
            "stig_id": "WN22-DC-000010",
            "severity": "CAT_II",
            "status": "Open",
            "finding_details": "Domain controller audit policy not configured per STIG requirements",
            "comments": "",
            "asset_id": "dc01.example.com",
            "stig_name": "Windows Server 2022 STIG",
            "stig_version": "V1R1",
            "mapped_nist_controls": ["CM-6", "AU-2"],
            "cci_ids": ["CCI-000366"],
        },
        {
            "vuln_id": "V-254240",
            "rule_id": "SV-254240r848547_rule",
            "stig_id": "WN22-DC-000020",
            "severity": "CAT_I",
            "status": "Not_A_Finding",
            "finding_details": "",
            "comments": "Verified via Group Policy",
            "asset_id": "dc01.example.com",
            "stig_name": "Windows Server 2022 STIG",
            "stig_version": "V1R1",
            "mapped_nist_controls": ["AC-3", "IA-7"],
            "cci_ids": ["CCI-000213", "CCI-000803"],
        },
    ]
