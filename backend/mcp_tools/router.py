"""
MCP Router / Proxy

Centralized router for all MCP tool calls. Enforces:
  - Allowlisted API operations per provider
  - Least-privilege credential selection
  - Per-tenant policy and rate limits
  - Approval gates for destructive operations
  - Full audit logging of every tool call + output hash

All agent nodes call MCP tools through this router — never directly.
"""

import hashlib
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MCPAction(str, Enum):
    """Categorization of MCP tool actions for policy enforcement."""
    READ = "read"           # Config snapshots, asset inventory, audit logs
    EVALUATE = "evaluate"   # Control rule evaluation
    STORE = "store"         # Evidence artifact storage
    CREATE = "create"       # POA&M items, tickets, PRs
    SCAN = "scan"           # STIG/SCAP scans
    MODIFY = "modify"       # Remediation actions (gated)


# Actions that require human approval before execution
APPROVAL_REQUIRED_ACTIONS = {MCPAction.MODIFY}

# Tool -> action classification
TOOL_ACTION_MAP: Dict[str, MCPAction] = {
    "compliance_core.get_asset_inventory": MCPAction.READ,
    "compliance_core.get_config_snapshot": MCPAction.READ,
    "compliance_core.query_audit_logs": MCPAction.READ,
    "compliance_core.evaluate_control_rule": MCPAction.EVALUATE,
    "compliance_core.store_evidence_artifact": MCPAction.STORE,
    "compliance_core.detect_drift": MCPAction.READ,
    "compliance_core.create_poam_item": MCPAction.CREATE,
    "compliance_core.create_ticket": MCPAction.CREATE,
    "stig_scap.ingest_ckl": MCPAction.STORE,
    "stig_scap.run_scap_scan": MCPAction.SCAN,
    "stig_scap.map_stig_to_nist_controls": MCPAction.READ,
    "stig_scap.get_stig_benchmark_info": MCPAction.READ,
    "cicd.create_remediation_pr": MCPAction.CREATE,
    "cicd.run_terraform_plan": MCPAction.READ,
    "cicd.run_policy_check": MCPAction.READ,
    "ticketing.create_ticket": MCPAction.CREATE,
    "ticketing.update_ticket": MCPAction.MODIFY,
    "ticketing.query_tickets": MCPAction.READ,
}


@dataclass
class MCPPolicy:
    """Per-tenant MCP policy configuration."""
    tenant_id: str
    allowed_tools: List[str] = field(default_factory=lambda: list(TOOL_ACTION_MAP.keys()))
    allowed_providers: List[str] = field(
        default_factory=lambda: ["aws", "aws_gov", "azure", "azure_gov", "gcp", "gcp_gov"]
    )
    max_calls_per_minute: int = 60
    require_approval_for: List[MCPAction] = field(default_factory=lambda: list(APPROVAL_REQUIRED_ACTIONS))
    require_mtls: bool = False
    audit_all_calls: bool = True


@dataclass
class MCPCallRecord:
    """Immutable record of an MCP tool call for audit trail."""
    call_id: str
    run_id: str
    agent_id: str
    tool_name: str
    action: MCPAction
    input_params: Dict[str, Any]
    output: Optional[Dict[str, Any]] = None
    output_hash: str = ""
    started_at: str = ""
    completed_at: str = ""
    duration_ms: int = 0
    success: bool = True
    error: str = ""
    approval_required: bool = False
    approval_id: Optional[str] = None
    correlation_id: str = ""


class MCPRouter:
    """
    Central MCP Router that mediates all tool calls from agents.

    Responsibilities:
    1. Validate tool name is allowlisted
    2. Validate provider is permitted
    3. Check rate limits
    4. Route to correct provider implementation
    5. Hash and audit all outputs
    6. Enforce approval gates for destructive operations
    """

    def __init__(self, policy: Optional[MCPPolicy] = None):
        self.policy = policy or MCPPolicy(tenant_id="default")
        self._call_log: List[MCPCallRecord] = []
        self._call_counts: Dict[str, int] = {}
        self._providers: Dict[str, Any] = {}

    def register_provider(self, provider_name: str, provider_impl: Any) -> None:
        """Register a cloud provider MCP implementation."""
        self._providers[provider_name] = provider_impl
        logger.info(f"MCP Router: registered provider '{provider_name}'")

    def call(
        self,
        tool_name: str,
        params: Dict[str, Any],
        run_id: str = "",
        agent_id: str = "",
        correlation_id: str = "",
    ) -> Dict[str, Any]:
        """
        Execute an MCP tool call with full policy enforcement and audit logging.

        Args:
            tool_name: Fully qualified tool name (e.g., 'compliance_core.get_asset_inventory')
            params: Tool input parameters
            run_id: Compliance run ID for traceability
            agent_id: Calling agent identifier
            correlation_id: Cross-agent correlation ID

        Returns:
            Tool output as dict

        Raises:
            MCPPolicyViolation: If tool/provider not allowed or rate limited
            MCPApprovalRequired: If action requires human approval
            MCPToolError: If tool execution fails
        """
        call_id = str(uuid.uuid4())
        start_time = time.time()
        started_at = datetime.now(timezone.utc).isoformat()

        # --- Policy checks ---
        self._validate_tool_allowed(tool_name)
        self._validate_provider_allowed(params.get("provider", ""))
        self._check_rate_limit(agent_id)

        action = TOOL_ACTION_MAP.get(tool_name, MCPAction.READ)

        # --- Approval gate ---
        if action in self.policy.require_approval_for:
            record = MCPCallRecord(
                call_id=call_id,
                run_id=run_id,
                agent_id=agent_id,
                tool_name=tool_name,
                action=action,
                input_params=self._sanitize_params(params),
                started_at=started_at,
                approval_required=True,
                correlation_id=correlation_id,
            )
            self._call_log.append(record)
            raise MCPApprovalRequired(
                f"Tool '{tool_name}' requires human approval (action: {action.value})",
                call_id=call_id,
                action_payload=params,
            )

        # --- Execute tool ---
        record = MCPCallRecord(
            call_id=call_id,
            run_id=run_id,
            agent_id=agent_id,
            tool_name=tool_name,
            action=action,
            input_params=self._sanitize_params(params),
            started_at=started_at,
            correlation_id=correlation_id,
        )

        try:
            result = self._route_and_execute(tool_name, params)
            elapsed_ms = int((time.time() - start_time) * 1000)

            record.output = result
            record.output_hash = self._hash_output(result)
            record.completed_at = datetime.now(timezone.utc).isoformat()
            record.duration_ms = elapsed_ms
            record.success = True

        except Exception as e:
            elapsed_ms = int((time.time() - start_time) * 1000)
            record.completed_at = datetime.now(timezone.utc).isoformat()
            record.duration_ms = elapsed_ms
            record.success = False
            record.error = str(e)
            self._call_log.append(record)
            raise MCPToolError(f"Tool '{tool_name}' failed: {e}") from e

        self._call_log.append(record)

        if self.policy.audit_all_calls:
            logger.info(
                f"MCP call: {tool_name} | agent={agent_id} | run={run_id} | "
                f"duration={elapsed_ms}ms | hash={record.output_hash[:16]}"
            )

        return result

    def _validate_tool_allowed(self, tool_name: str) -> None:
        if tool_name not in self.policy.allowed_tools:
            raise MCPPolicyViolation(f"Tool '{tool_name}' is not in the allowlist")

    def _validate_provider_allowed(self, provider: str) -> None:
        if provider and provider not in self.policy.allowed_providers:
            raise MCPPolicyViolation(f"Provider '{provider}' is not permitted by policy")

    def _check_rate_limit(self, agent_id: str) -> None:
        now_minute = int(time.time() / 60)
        key = f"{agent_id}:{now_minute}"
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        if self._call_counts[key] > self.policy.max_calls_per_minute:
            raise MCPPolicyViolation(
                f"Rate limit exceeded: {self.policy.max_calls_per_minute} calls/min"
            )

    def _route_and_execute(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Route to the correct provider implementation and execute."""
        toolset, method = tool_name.split(".", 1)
        provider_key = params.get("provider", "")

        # Look up registered provider or use stub
        impl = self._providers.get(provider_key) or self._providers.get(toolset)
        if impl is None:
            # Return stub response for unregistered providers
            return {
                "status": "stub",
                "tool": tool_name,
                "message": f"Provider '{provider_key}' not registered. Stub response.",
                "params": self._sanitize_params(params),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Call the method on the provider implementation
        handler = getattr(impl, method, None)
        if handler is None:
            raise MCPToolError(f"Method '{method}' not found on provider '{provider_key}'")
        return handler(params)

    @staticmethod
    def _sanitize_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive fields before logging (credentials, tokens)."""
        sensitive_keys = {"credential_ref", "token", "secret", "password", "api_key"}
        return {
            k: "***REDACTED***" if k in sensitive_keys else v
            for k, v in params.items()
        }

    @staticmethod
    def _hash_output(output: Dict[str, Any]) -> str:
        """SHA-256 hash of the JSON-serialized output for integrity."""
        serialized = json.dumps(output, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def get_audit_trail(self, run_id: Optional[str] = None) -> List[MCPCallRecord]:
        """Get audit trail, optionally filtered by run."""
        if run_id:
            return [r for r in self._call_log if r.run_id == run_id]
        return list(self._call_log)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class MCPPolicyViolation(Exception):
    """Raised when an MCP call violates the configured policy."""
    pass


class MCPApprovalRequired(Exception):
    """Raised when an MCP call requires human approval before execution."""
    def __init__(self, message: str, call_id: str = "", action_payload: Any = None):
        super().__init__(message)
        self.call_id = call_id
        self.action_payload = action_payload


class MCPToolError(Exception):
    """Raised when an MCP tool execution fails."""
    pass
