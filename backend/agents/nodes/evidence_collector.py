"""
Node 4: Evidence Collector Agent (MCP)

Executes the evidence collection plan by calling MCP tools across
all cloud providers. Stores collected evidence in the vault with
hashes and metadata. Multi-cloud aware.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)


def evidence_collector(state: ComplianceState, mcp_router=None) -> ComplianceState:
    """
    Collect evidence artifacts by executing MCP tool calls per the evidence plan.

    For each entry in evidence_plan.needs_collection:
    1. Call the appropriate MCP tool via the router
    2. Store the result as an evidence artifact in the vault
    3. Record artifact metadata in state
    """
    logger.info(f"[EvidenceCollector] Starting evidence collection for run {state.run_id}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "evidence_collector_agent",
        "action": "collect_evidence",
        "input_summary": {"plan_entries": len(state.evidence_plan)},
        "output_summary": {},
        "duration_ms": 0,
    }

    collected_count = 0
    error_count = 0

    for plan_key, plan_entry in state.evidence_plan.items():
        for source in plan_entry.get("sources", []):
            if source.get("evidence_type") in plan_entry.get("existing_fresh", []):
                continue  # Skip — fresh evidence already exists

            tool_name = source.get("mcp_tool", "")
            provider = source.get("provider", "")
            evidence_type = source.get("evidence_type", "")
            control_id = plan_entry.get("control_id", "")

            if not tool_name:
                continue

            # Build MCP tool parameters
            params = _build_tool_params(
                tool_name=tool_name,
                provider=provider,
                system_id=state.scope.system_id,
                scope=state.scope.boundary,
                control_id=control_id,
            )

            if mcp_router:
                try:
                    result = mcp_router.call(
                        tool_name=tool_name,
                        params=params,
                        run_id=state.run_id,
                        agent_id="evidence_collector_agent",
                    )

                    # Store result as evidence artifact
                    artifact_record = _store_evidence(
                        mcp_router=mcp_router,
                        system_id=state.scope.system_id,
                        evidence_type=evidence_type,
                        provider=provider,
                        control_id=control_id,
                        result=result,
                    )

                    if artifact_record:
                        state.evidence_artifacts.append(artifact_record)
                        collected_count += 1

                except Exception as e:
                    logger.error(
                        f"[EvidenceCollector] MCP call failed: {tool_name} "
                        f"provider={provider}: {e}"
                    )
                    error_count += 1
                    state.errors.append({
                        "agent": "evidence_collector_agent",
                        "error": f"MCP call {tool_name} failed for {provider}: {str(e)[:200]}",
                    })
            else:
                # Stub mode: record what would have been collected
                state.evidence_artifacts.append({
                    "artifact_id": f"stub-{plan_key}-{provider}",
                    "artifact_type": evidence_type,
                    "provider": provider,
                    "hash": "",
                    "storage_uri": "",
                    "control_ids": [control_id] if control_id != "__asset_inventory" else [],
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "stub": True,
                })
                collected_count += 1

    trace_entry["output_summary"] = {
        "collected": collected_count,
        "errors": error_count,
        "total_artifacts": len(state.evidence_artifacts),
    }
    state.agent_trace.append(trace_entry)

    logger.info(
        f"[EvidenceCollector] Collection complete: {collected_count} artifacts, "
        f"{error_count} errors"
    )
    return state


def _build_tool_params(
    tool_name: str,
    provider: str,
    system_id: str,
    scope: Dict[str, Any],
    control_id: str,
) -> Dict[str, Any]:
    """Build MCP tool parameters based on tool name and context."""
    base_params = {
        "provider": provider,
        "system_id": system_id,
        "scope": scope,
    }

    if "get_asset_inventory" in tool_name:
        base_params["time"] = {"as_of": datetime.now(timezone.utc).isoformat()}

    elif "get_config_snapshot" in tool_name:
        # Determine resource type from control family
        family = control_id.split("-")[0] if "-" in control_id else ""
        resource_type_map = {
            "AC": "iam",
            "AU": "logging",
            "CM": "compute",
            "IA": "iam",
            "SC": "network",
            "SI": "compute",
        }
        base_params["resource_type"] = resource_type_map.get(family, "compute")

    elif "query_audit_logs" in tool_name:
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        base_params["query"] = {"event_types": []}
        base_params["time_range"] = {
            "start": (now - timedelta(days=7)).isoformat(),
            "end": now.isoformat(),
        }

    return base_params


def _store_evidence(
    mcp_router,
    system_id: str,
    evidence_type: str,
    provider: str,
    control_id: str,
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """Store MCP tool result as an evidence artifact via the vault."""
    try:
        store_result = mcp_router.call(
            tool_name="compliance_core.store_evidence_artifact",
            params={
                "system_id": system_id,
                "artifact_type": evidence_type,
                "content_uri": "inline",  # In production: upload to object storage first
                "tags": {
                    "control_ids": [control_id] if control_id != "__asset_inventory" else [],
                    "provider": provider,
                    "environment": "production",
                },
            },
            run_id="",
            agent_id="evidence_collector_agent",
        )

        return {
            "artifact_id": store_result.get("artifact_id", ""),
            "artifact_type": evidence_type,
            "provider": provider,
            "hash": store_result.get("hash_sha256", ""),
            "storage_uri": store_result.get("storage_uri", ""),
            "control_ids": [control_id] if control_id != "__asset_inventory" else [],
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Evidence storage failed: {e}")
        return {
            "artifact_id": "",
            "artifact_type": evidence_type,
            "provider": provider,
            "hash": "",
            "storage_uri": "",
            "control_ids": [control_id] if control_id != "__asset_inventory" else [],
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
        }
