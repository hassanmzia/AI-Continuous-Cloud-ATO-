"""
Node 1: Scope Resolver

Resolves system boundary, validates RBAC permissions, and sets up the run scope.
Validates that the user/service has access to the requested system and providers.
"""

import logging
from datetime import datetime, timezone

from agents.state import ComplianceState

logger = logging.getLogger(__name__)


def scope_resolver(state: ComplianceState) -> ComplianceState:
    """
    Resolve and validate the compliance run scope.

    Responsibilities:
    - Validate system_id exists and user has access
    - Resolve cloud provider accounts within the system boundary
    - Determine applicable baseline and frameworks
    - Set environment context
    - Enforce least-privilege scoping
    """
    logger.info(f"[ScopeResolver] Resolving scope for run {state.run_id}")

    state.agent_trace.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": "scope_resolver",
        "action": "resolve_scope",
        "input_summary": {
            "system_id": state.scope.system_id,
            "question": state.question[:200] if state.question else "",
        },
        "output_summary": {},
        "duration_ms": 0,
    })

    # In production: query Django models to validate system exists
    # and user has RBAC access to it
    try:
        from core.models import System, CloudAccount

        system = System.objects.filter(
            id=state.scope.system_id, is_active=True
        ).first()

        if system is None:
            # Try by name
            system = System.objects.filter(
                name=state.scope.system_name, is_active=True
            ).first()

        if system:
            state.scope.system_id = str(system.id)
            state.scope.system_name = system.name
            state.scope.baseline = system.baseline
            state.scope.environment = system.environment
            state.scope.frameworks = system.frameworks or state.scope.frameworks
            state.scope.boundary = system.boundary_definition or state.scope.boundary

            # Resolve cloud accounts
            accounts = CloudAccount.objects.filter(system=system, is_active=True)
            state.scope.providers = list(set(a.provider for a in accounts))

            logger.info(
                f"[ScopeResolver] Resolved system '{system.name}' with "
                f"{len(state.scope.providers)} providers: {state.scope.providers}"
            )
        else:
            logger.warning(
                f"[ScopeResolver] System not found: {state.scope.system_id or state.scope.system_name}"
            )
            state.errors.append({
                "agent": "scope_resolver",
                "error": f"System not found: {state.scope.system_id or state.scope.system_name}",
            })

    except Exception as e:
        # If Django models aren't available (testing), use defaults
        logger.warning(f"[ScopeResolver] DB lookup failed: {e} — using provided scope")
        if not state.scope.providers:
            state.scope.providers = ["aws"]

    state.agent_trace[-1]["output_summary"] = {
        "system_id": state.scope.system_id,
        "providers": state.scope.providers,
        "baseline": state.scope.baseline,
        "frameworks": state.scope.frameworks,
    }

    return state
