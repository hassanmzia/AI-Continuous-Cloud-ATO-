"""
Node 5: Drift Detection Agent (MCP + multi-hop)

Compares current cloud configuration snapshots against the last attested
baselines. Uses audit logs to attribute changes (who/when). Detects:
  - Config drift (security groups, IAM policies, encryption settings)
  - Identity drift (new roles, privilege escalation, unused accounts)
  - Network drift (new endpoints, changed firewall rules, exposed ports)
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)

# Drift severity classification
DRIFT_SEVERITY_RULES = {
    "iam": {"new_admin_role": "critical", "policy_change": "high", "new_user": "medium"},
    "network": {"new_public_endpoint": "critical", "sg_rule_added": "high", "subnet_change": "medium"},
    "storage": {"public_access_enabled": "critical", "encryption_disabled": "critical"},
    "encryption": {"key_rotation_disabled": "high", "key_deleted": "critical"},
    "logging": {"trail_disabled": "critical", "log_retention_reduced": "high"},
}


def drift_detection_agent(state: ComplianceState, mcp_router=None) -> ComplianceState:
    """
    Detect configuration drift across all providers.

    Workflow:
    1. For each provider, retrieve the last baseline snapshot (from evidence vault)
    2. Get current snapshot via MCP
    3. Diff baseline vs current
    4. Use audit logs to attribute changes
    5. Classify severity and map to affected controls
    """
    logger.info(f"[DriftDetection] Starting drift analysis for {len(state.scope.providers)} providers")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "drift_detection_agent",
        "action": "detect_drift",
        "input_summary": {
            "providers": state.scope.providers,
            "evidence_count": len(state.evidence_artifacts),
        },
        "output_summary": {},
        "duration_ms": 0,
    }

    drift_events: List[Dict[str, Any]] = []

    for provider in state.scope.providers:
        provider_artifacts = [
            a for a in state.evidence_artifacts
            if a.get("provider") == provider and a.get("artifact_type") == "config_snapshot"
        ]

        if not provider_artifacts:
            logger.info(f"[DriftDetection] No config snapshots for {provider} — skipping")
            continue

        # In production: compare current vs baseline via MCP detect_drift tool
        if mcp_router:
            try:
                for artifact in provider_artifacts:
                    result = mcp_router.call(
                        tool_name="compliance_core.detect_drift",
                        params={
                            "provider": provider,
                            "system_id": state.scope.system_id,
                            "resource_type": _infer_resource_type(artifact),
                            "baseline_artifact_id": _get_baseline_artifact(
                                state.scope.system_id, provider, artifact.get("artifact_type", "")
                            ),
                            "current_artifact_id": artifact.get("artifact_id", ""),
                        },
                        run_id=state.run_id,
                        agent_id="drift_detection_agent",
                    )

                    if result.get("drift_detected"):
                        for event in result.get("drift_events", []):
                            event["provider"] = provider
                            drift_events.append(event)

            except Exception as e:
                logger.error(f"[DriftDetection] MCP drift call failed for {provider}: {e}")
                state.errors.append({
                    "agent": "drift_detection_agent",
                    "error": f"Drift detection failed for {provider}: {str(e)[:200]}",
                })
        else:
            # Stub: generate sample drift events for demonstration
            drift_events.extend(_generate_stub_drift(provider))

    # Classify severity and map to controls
    for event in drift_events:
        if "severity" not in event or not event["severity"]:
            event["severity"] = _classify_severity(event)
        if "affected_controls" not in event or not event["affected_controls"]:
            event["affected_controls"] = _map_to_controls(event)

    state.drift_events = drift_events

    trace_entry["output_summary"] = {
        "total_drift_events": len(drift_events),
        "by_severity": _count_by_severity(drift_events),
    }
    state.agent_trace.append(trace_entry)

    logger.info(f"[DriftDetection] Found {len(drift_events)} drift events")
    return state


def _infer_resource_type(artifact: Dict[str, Any]) -> str:
    """Infer resource type from artifact metadata."""
    control_ids = artifact.get("control_ids", [])
    if control_ids:
        family = control_ids[0].split("-")[0] if "-" in control_ids[0] else ""
        type_map = {"AC": "iam", "AU": "logging", "CM": "compute", "SC": "network"}
        return type_map.get(family, "compute")
    return "compute"


def _get_baseline_artifact(system_id: str, provider: str, artifact_type: str) -> str:
    """Get the last attested baseline artifact ID."""
    try:
        from core.models import EvidenceArtifact
        baseline = EvidenceArtifact.objects.filter(
            system_id=system_id,
            provider=provider,
            artifact_type=artifact_type,
        ).order_by("-collected_at").first()
        return str(baseline.id) if baseline else ""
    except Exception:
        return ""


def _classify_severity(event: Dict[str, Any]) -> str:
    """Classify drift event severity."""
    resource_type = event.get("resource_type", "").lower()
    field = event.get("field", "").lower()

    rules = DRIFT_SEVERITY_RULES.get(resource_type, {})
    for pattern, severity in rules.items():
        if pattern in field:
            return severity
    return "medium"


def _map_to_controls(event: Dict[str, Any]) -> List[str]:
    """Map a drift event to affected NIST 800-53 controls."""
    resource_type = event.get("resource_type", "").lower()
    control_map = {
        "iam": ["AC-2", "AC-3", "AC-6", "IA-2", "IA-5"],
        "network": ["SC-7", "SC-8", "AC-4"],
        "storage": ["SC-28", "AC-3"],
        "encryption": ["SC-12", "SC-13", "SC-28"],
        "logging": ["AU-2", "AU-3", "AU-6", "AU-12"],
        "compute": ["CM-2", "CM-6", "CM-7"],
    }
    return control_map.get(resource_type, ["CM-3", "CM-6"])


def _count_by_severity(events: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        sev = e.get("severity", "unknown")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _generate_stub_drift(provider: str) -> List[Dict[str, Any]]:
    """Generate stub drift events for demonstration."""
    return [
        {
            "resource_id": f"{provider}-sg-12345",
            "resource_type": "network",
            "field": "sg_rule_added",
            "baseline_value": {"inbound_rules": 3},
            "current_value": {"inbound_rules": 5},
            "changed_by": "admin@example.com",
            "changed_at": datetime.now(timezone.utc).isoformat(),
            "severity": "high",
            "affected_controls": ["SC-7", "AC-4"],
            "provider": provider,
        },
    ]
