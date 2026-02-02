"""
Node 2: Control Mapping Agent (RAG)

Uses RAG to map applicable controls from NIST 800-53, FedRAMP, RMF, and STIG
based on the system's baseline and boundary. Produces a structured control map
with cross-framework mappings, owners, and required evidence types.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

from agents.state import ComplianceState

logger = logging.getLogger(__name__)

# FedRAMP baseline control families (simplified — full list in control catalog)
FEDRAMP_FAMILIES = {
    "fedramp_low": [
        "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR",
        "MA", "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI",
    ],
    "fedramp_mod": [
        "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR",
        "MA", "MP", "PE", "PL", "PM", "PS", "RA", "SA", "SC", "SI", "SR",
    ],
    "fedramp_high": [
        "AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR",
        "MA", "MP", "PE", "PL", "PM", "PS", "RA", "SA", "SC", "SI", "SR",
    ],
}


def control_mapping_agent(state: ComplianceState) -> ComplianceState:
    """
    Map applicable controls using RAG over compliance knowledge base.

    This agent:
    1. Determines which control families apply based on baseline
    2. Retrieves control definitions from the vector store
    3. Retrieves cross-framework mappings (NIST <-> STIG via CCI)
    4. Identifies control owners and implementation statements from SSP
    5. Produces a structured control_map in state
    """
    logger.info(f"[ControlMapping] Mapping controls for baseline={state.scope.baseline}")

    trace_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "control_mapping_agent",
        "action": "map_controls",
        "input_summary": {
            "baseline": state.scope.baseline,
            "frameworks": state.scope.frameworks,
        },
        "output_summary": {},
        "duration_ms": 0,
    }

    control_map: Dict[str, Any] = {}

    # Step 1: Get applicable control families
    families = FEDRAMP_FAMILIES.get(state.scope.baseline, FEDRAMP_FAMILIES["fedramp_mod"])

    # Step 2: Query control catalog from DB
    try:
        from core.models import ControlCatalog, ControlMapping

        for framework in state.scope.frameworks:
            controls = ControlCatalog.objects.filter(framework=framework)
            if state.scope.baseline != "custom":
                controls = controls.filter(family__in=families)

            for ctrl in controls:
                key = f"{ctrl.framework}:{ctrl.control_id}"
                control_map[key] = {
                    "control_id": ctrl.control_id,
                    "framework": ctrl.framework,
                    "title": ctrl.title,
                    "family": ctrl.family,
                    "description": ctrl.description[:500],
                    "baseline_impact": ctrl.baseline_impact,
                    "assessment_objective": ctrl.assessment_objective[:500],
                    "cross_mappings": [],
                    "required_evidence_types": _get_required_evidence(ctrl.family),
                    "monitoring_frequency": _get_monitoring_frequency(ctrl.family),
                }

                # Add cross-framework mappings
                mappings = ControlMapping.objects.filter(
                    source_framework=ctrl.framework,
                    source_control_id=ctrl.control_id,
                )
                for m in mappings:
                    control_map[key]["cross_mappings"].append({
                        "target_framework": m.target_framework,
                        "target_control_id": m.target_control_id,
                        "cci_id": m.cci_id,
                        "srg_id": m.srg_id,
                    })

    except Exception as e:
        logger.warning(f"[ControlMapping] DB query failed: {e} — using RAG fallback")
        # RAG fallback: retrieve from vector store
        control_map = _rag_fallback_control_mapping(state.scope.baseline, families)

    # Step 3: Enhance with RAG (SSP statements, implementation details)
    control_map = _enrich_with_rag(control_map, state.scope.system_id)

    state.control_map = control_map

    trace_entry["output_summary"] = {
        "total_controls_mapped": len(control_map),
        "frameworks": list(set(v.get("framework", "") for v in control_map.values())),
    }
    state.agent_trace.append(trace_entry)

    logger.info(f"[ControlMapping] Mapped {len(control_map)} controls")
    return state


def _get_required_evidence(family: str) -> List[str]:
    """Get required evidence types for a control family."""
    evidence_map = {
        "AC": ["config_snapshot", "log_export", "policy_doc"],
        "AU": ["config_snapshot", "log_export"],
        "CM": ["config_snapshot", "scan_report"],
        "IA": ["config_snapshot", "policy_doc"],
        "SC": ["config_snapshot", "scan_report"],
        "SI": ["scan_report", "log_export"],
    }
    return evidence_map.get(family, ["config_snapshot"])


def _get_monitoring_frequency(family: str) -> str:
    """Get recommended monitoring frequency for a control family."""
    frequency_map = {
        "AC": "monthly",
        "AU": "weekly",
        "CM": "daily",
        "IA": "monthly",
        "SC": "monthly",
        "SI": "weekly",
        "CA": "annually",
        "RA": "quarterly",
    }
    return frequency_map.get(family, "monthly")


def _rag_fallback_control_mapping(baseline: str, families: List[str]) -> Dict[str, Any]:
    """Fallback control mapping using RAG when DB is unavailable."""
    try:
        from agents.rag.vector_store import VectorStoreManager

        vs = VectorStoreManager()
        results = vs.similarity_search(
            query=f"NIST 800-53 controls for {baseline} baseline",
            k=50,
            filter={"doc_type": "nist_control"},
        )

        control_map = {}
        for doc in results:
            ctrl_id = doc.metadata.get("control_id", "")
            framework = doc.metadata.get("framework", "nist_800_53_r5")
            if ctrl_id:
                key = f"{framework}:{ctrl_id}"
                control_map[key] = {
                    "control_id": ctrl_id,
                    "framework": framework,
                    "title": "",
                    "family": doc.metadata.get("family", ""),
                    "description": doc.page_content[:500],
                    "cross_mappings": [],
                    "required_evidence_types": ["config_snapshot"],
                    "monitoring_frequency": "monthly",
                }
        return control_map
    except Exception:
        return {}


def _enrich_with_rag(control_map: Dict[str, Any], system_id: str) -> Dict[str, Any]:
    """Enrich control map with SSP statements and implementation details via RAG."""
    try:
        from agents.rag.vector_store import VectorStoreManager

        vs = VectorStoreManager()
        for key, ctrl in control_map.items():
            results = vs.similarity_search(
                query=f"SSP implementation for {ctrl['control_id']}",
                k=2,
                filter={"doc_type": "ssp_statement", "control_id": ctrl["control_id"]},
            )
            if results:
                ctrl["ssp_narrative"] = results[0].page_content[:500]
    except Exception as e:
        logger.debug(f"RAG enrichment skipped: {e}")

    return control_map
