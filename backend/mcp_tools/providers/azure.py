"""
Azure + Azure Government MCP Provider Implementation.

Translates canonical MCP compliance_core tool calls into Azure API calls.
Supports both commercial (azure) and Government (azure_gov) clouds.

Azure Services used:
  - Resource Graph: Asset inventory, config queries
  - Azure Policy: Compliance state per policy assignment
  - Defender for Cloud: Security posture, recommendations
  - Activity Logs: Audit trail
  - Entra ID (Azure AD): Identity/RBAC config
  - Azure Monitor: Diagnostic settings, log queries
  - Guest Configuration: OS-level STIG compliance
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

AZURE_ENDPOINTS = {
    "azure": {
        "resource_manager": "https://management.azure.com",
        "graph": "https://graph.microsoft.com",
        "authority": "https://login.microsoftonline.com",
    },
    "azure_gov": {
        "resource_manager": "https://management.usgovcloudapi.net",
        "graph": "https://graph.microsoft.us",
        "authority": "https://login.microsoftonline.us",
    },
}


class AzureProvider:
    """
    Azure MCP provider — implements canonical compliance_core methods
    against Azure APIs (commercial + Government).
    """

    def __init__(self, provider_type: str = "azure", credentials: Optional[Dict] = None):
        self.provider_type = provider_type
        self.endpoints = AZURE_ENDPOINTS[provider_type]
        self._credentials = credentials
        self._initialized = False
        logger.info(f"Azure MCP Provider initialized: {provider_type}")

    def _ensure_client(self):
        """Lazy-initialize Azure clients."""
        if self._initialized:
            return True
        try:
            from azure.identity import DefaultAzureCredential
            self._credential = DefaultAzureCredential(
                authority=self.endpoints["authority"]
            )
            self._initialized = True
            return True
        except ImportError:
            logger.warning("azure-identity not installed — returning stub responses")
            return False

    # ----- compliance_core.get_asset_inventory -----
    def get_asset_inventory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate assets using Azure Resource Graph."""
        scope = params.get("scope", {})
        subscriptions = scope.get("accounts", [])
        resource_groups = scope.get("resource_groups", [])
        tags = scope.get("tags", {})

        assets: List[Dict[str, Any]] = []

        if not self._ensure_client():
            assets.append({
                "asset_id": "stub-azure",
                "resource_type": "stub",
                "name": "Stub resource (azure SDK not available)",
                "region": "N/A",
                "tags": tags,
                "provider_native_id": "N/A",
                "status": "stub",
            })
        else:
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import (
                    QueryRequest,
                    QueryRequestOptions,
                )

                rg_client = ResourceGraphClient(self._credential)
                query = "Resources | project id, name, type, location, tags, resourceGroup, subscriptionId"

                if resource_groups:
                    rg_filter = ", ".join(f"'{rg}'" for rg in resource_groups)
                    query += f" | where resourceGroup in ({rg_filter})"

                request = QueryRequest(
                    subscriptions=subscriptions,
                    query=query,
                    options=QueryRequestOptions(result_format="objectArray"),
                )
                response = rg_client.resources(request)

                for row in response.data:
                    assets.append({
                        "asset_id": row.get("id", ""),
                        "resource_type": row.get("type", ""),
                        "name": row.get("name", ""),
                        "region": row.get("location", ""),
                        "tags": row.get("tags", {}),
                        "provider_native_id": row.get("id", ""),
                        "status": "active",
                    })
            except Exception as e:
                logger.error(f"Azure asset inventory failed: {e}")
                assets.append({
                    "asset_id": "error-azure",
                    "resource_type": "error",
                    "name": str(e),
                    "region": "N/A",
                    "status": "error",
                })

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "assets": assets,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ----- compliance_core.get_config_snapshot -----
    def get_config_snapshot(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch configuration state using Azure Resource Graph and Policy."""
        resource_type = params.get("resource_type", "")
        scope = params.get("scope", {})

        azure_type_map = {
            "iam": "microsoft.authorization/roleassignments",
            "storage": "microsoft.storage/storageaccounts",
            "network": "microsoft.network/virtualnetworks",
            "compute": "microsoft.compute/virtualmachines",
            "kubernetes": "microsoft.containerservice/managedclusters",
            "database": "microsoft.sql/servers/databases",
            "encryption": "microsoft.keyvault/vaults",
            "logging": "microsoft.insights/diagnosticsettings",
        }

        resources: List[Dict[str, Any]] = []
        azure_type = azure_type_map.get(resource_type, resource_type)

        if not self._ensure_client():
            resources.append({
                "resource_id": "stub",
                "config": {"stub": True, "resource_type": resource_type, "azure_type": azure_type},
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "provider_native_id": "N/A",
            })
        else:
            try:
                from azure.mgmt.resourcegraph import ResourceGraphClient
                from azure.mgmt.resourcegraph.models import QueryRequest

                rg_client = ResourceGraphClient(self._credential)
                query = f"Resources | where type =~ '{azure_type}' | project id, name, type, properties, location"

                subscriptions = scope.get("accounts", [])
                request = QueryRequest(subscriptions=subscriptions, query=query)
                response = rg_client.resources(request)

                for row in response.data:
                    resources.append({
                        "resource_id": row.get("id", ""),
                        "config": row.get("properties", {}),
                        "last_modified": datetime.now(timezone.utc).isoformat(),
                        "provider_native_id": row.get("id", ""),
                    })
            except Exception as e:
                logger.error(f"Azure config snapshot failed: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "resource_type": resource_type,
            "resources": resources,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ----- compliance_core.query_audit_logs -----
    def query_audit_logs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query Azure Activity Logs for audit events."""
        query = params.get("query", {})
        time_range = params.get("time_range", {})

        events: List[Dict[str, Any]] = []

        if not self._ensure_client():
            events.append({
                "event_id": "stub",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "actor": "stub",
                "action": "stub",
                "resource": "stub",
                "result": "stub",
            })
        else:
            try:
                from azure.mgmt.monitor import MonitorManagementClient

                scope = params.get("scope", {})
                subscriptions = scope.get("accounts", [])
                if subscriptions:
                    monitor_client = MonitorManagementClient(
                        self._credential, subscriptions[0]
                    )
                    filter_str = f"eventTimestamp ge '{time_range.get('start', '')}' and eventTimestamp le '{time_range.get('end', '')}'"
                    for event in monitor_client.activity_logs.list(filter=filter_str):
                        events.append({
                            "event_id": event.event_data_id or "",
                            "timestamp": event.event_timestamp.isoformat() if event.event_timestamp else "",
                            "actor": event.caller or "",
                            "action": event.operation_name.value if event.operation_name else "",
                            "resource": event.resource_id or "",
                            "result": event.status.value if event.status else "",
                        })
            except Exception as e:
                logger.error(f"Azure audit log query failed: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "events": events,
            "total_count": len(events),
            "truncated": False,
        }

    # ----- compliance_core.evaluate_control_rule -----
    def evaluate_control_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate using Azure Policy compliance state + Defender for Cloud."""
        control_id = params.get("control_id", "")
        evidence_refs = params.get("evidence_refs", [])

        return {
            "control_id": control_id,
            "framework": params.get("framework", ""),
            "status": "manual_review_required",
            "confidence": 0.0,
            "rationale": f"Stub evaluation for {control_id} on Azure. "
                         f"Evidence refs: {evidence_refs}. "
                         "Connect Azure Policy / Defender for automated evaluation.",
            "evidence_citations": [],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
