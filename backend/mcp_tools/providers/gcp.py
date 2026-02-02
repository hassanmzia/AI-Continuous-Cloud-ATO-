"""
GCP + GCP Government MCP Provider Implementation.

Translates canonical MCP compliance_core tool calls into GCP API calls.
Supports both commercial (gcp) and Government (gcp_gov) clouds.

GCP Services used:
  - Cloud Asset Inventory: Asset enumeration + config
  - Cloud Logging: Audit logs (Admin Activity, Data Access, System Event)
  - Security Command Center: Security findings, posture
  - IAM: Identity and access management config
  - Organization Policy: Policy constraints
  - OS Config: OS-level patch/STIG compliance
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

GCP_ENDPOINTS = {
    "gcp": {
        "asset": "cloudasset.googleapis.com",
        "logging": "logging.googleapis.com",
        "scc": "securitycenter.googleapis.com",
    },
    "gcp_gov": {
        "asset": "cloudasset.googleapis.com",  # Gov endpoints configured via VPC-SC
        "logging": "logging.googleapis.com",
        "scc": "securitycenter.googleapis.com",
    },
}


class GCPProvider:
    """
    GCP MCP provider — implements canonical compliance_core methods
    against GCP APIs (commercial + Government).
    """

    def __init__(self, provider_type: str = "gcp", credentials: Optional[Dict] = None):
        self.provider_type = provider_type
        self.endpoints = GCP_ENDPOINTS[provider_type]
        self._credentials = credentials
        self._initialized = False
        logger.info(f"GCP MCP Provider initialized: {provider_type}")

    def _ensure_clients(self) -> bool:
        """Lazy-initialize GCP clients."""
        if self._initialized:
            return True
        try:
            from google.cloud import asset_v1
            self._asset_client = asset_v1.AssetServiceClient()
            self._initialized = True
            return True
        except ImportError:
            logger.warning("google-cloud-asset not installed — returning stub responses")
            return False
        except Exception as e:
            logger.warning(f"GCP client init failed: {e} — returning stub responses")
            return False

    # ----- compliance_core.get_asset_inventory -----
    def get_asset_inventory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate assets using Cloud Asset Inventory."""
        scope = params.get("scope", {})
        projects = scope.get("accounts", [])
        tags = scope.get("tags", {})

        assets: List[Dict[str, Any]] = []

        if not self._ensure_clients():
            assets.append({
                "asset_id": "stub-gcp",
                "resource_type": "stub",
                "name": "Stub resource (GCP SDK not available)",
                "region": "N/A",
                "tags": tags,
                "provider_native_id": "N/A",
                "status": "stub",
            })
        else:
            for project in projects:
                try:
                    parent = f"projects/{project}"
                    asset_types = [
                        "compute.googleapis.com/Instance",
                        "storage.googleapis.com/Bucket",
                        "container.googleapis.com/Cluster",
                        "sqladmin.googleapis.com/Instance",
                        "iam.googleapis.com/ServiceAccount",
                        "cloudkms.googleapis.com/CryptoKey",
                        "cloudresourcemanager.googleapis.com/Project",
                    ]

                    from google.cloud.asset_v1 import ListAssetsRequest

                    request = ListAssetsRequest(
                        parent=parent,
                        asset_types=asset_types,
                        content_type="RESOURCE",
                    )

                    for asset in self._asset_client.list_assets(request=request):
                        assets.append({
                            "asset_id": asset.name,
                            "resource_type": asset.asset_type,
                            "name": asset.resource.data.get("name", "") if asset.resource else "",
                            "region": asset.resource.location if asset.resource else "",
                            "tags": tags,
                            "provider_native_id": asset.name,
                            "status": "active",
                        })
                except Exception as e:
                    logger.error(f"GCP asset inventory failed for project {project}: {e}")
                    assets.append({
                        "asset_id": f"error-{project}",
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
        """Fetch configuration state using Cloud Asset Inventory."""
        resource_type = params.get("resource_type", "")
        scope = params.get("scope", {})

        gcp_type_map = {
            "iam": ["iam.googleapis.com/ServiceAccount", "iam.googleapis.com/Role"],
            "storage": ["storage.googleapis.com/Bucket"],
            "network": ["compute.googleapis.com/Network", "compute.googleapis.com/Firewall"],
            "compute": ["compute.googleapis.com/Instance"],
            "kubernetes": ["container.googleapis.com/Cluster"],
            "database": ["sqladmin.googleapis.com/Instance"],
            "encryption": ["cloudkms.googleapis.com/CryptoKey"],
            "logging": ["logging.googleapis.com/LogSink"],
        }

        resources: List[Dict[str, Any]] = []
        gcp_types = gcp_type_map.get(resource_type, [])

        if not self._ensure_clients():
            resources.append({
                "resource_id": "stub",
                "config": {"stub": True, "resource_type": resource_type},
                "last_modified": datetime.now(timezone.utc).isoformat(),
                "provider_native_id": "N/A",
            })
        else:
            projects = scope.get("accounts", [])
            for project in projects:
                for asset_type in gcp_types:
                    try:
                        from google.cloud.asset_v1 import ListAssetsRequest

                        request = ListAssetsRequest(
                            parent=f"projects/{project}",
                            asset_types=[asset_type],
                            content_type="RESOURCE",
                        )
                        for asset in self._asset_client.list_assets(request=request):
                            resources.append({
                                "resource_id": asset.name,
                                "config": dict(asset.resource.data) if asset.resource and asset.resource.data else {},
                                "last_modified": asset.update_time.isoformat() if asset.update_time else "",
                                "provider_native_id": asset.name,
                            })
                    except Exception as e:
                        logger.error(f"GCP config snapshot failed for {asset_type}: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "resource_type": resource_type,
            "resources": resources,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ----- compliance_core.query_audit_logs -----
    def query_audit_logs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query Cloud Logging for audit events."""
        query = params.get("query", {})
        time_range = params.get("time_range", {})
        scope = params.get("scope", {})
        projects = scope.get("accounts", [])

        events: List[Dict[str, Any]] = []

        if not self._ensure_clients():
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
                from google.cloud import logging as gcp_logging

                logging_client = gcp_logging.Client()
                for project in projects:
                    filter_str = (
                        f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2Factivity" '
                        f'AND timestamp>="{time_range.get("start", "")}" '
                        f'AND timestamp<="{time_range.get("end", "")}"'
                    )

                    for entry in logging_client.list_entries(
                        filter_=filter_str,
                        max_results=params.get("max_results", 50),
                    ):
                        payload = entry.payload if hasattr(entry, "payload") else {}
                        events.append({
                            "event_id": entry.insert_id or "",
                            "timestamp": entry.timestamp.isoformat() if entry.timestamp else "",
                            "actor": payload.get("authenticationInfo", {}).get("principalEmail", ""),
                            "action": payload.get("methodName", ""),
                            "resource": payload.get("resourceName", ""),
                            "result": payload.get("status", {}).get("message", ""),
                        })
            except Exception as e:
                logger.error(f"GCP audit log query failed: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "events": events,
            "total_count": len(events),
            "truncated": False,
        }

    # ----- compliance_core.evaluate_control_rule -----
    def evaluate_control_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate using Security Command Center findings."""
        control_id = params.get("control_id", "")
        evidence_refs = params.get("evidence_refs", [])

        return {
            "control_id": control_id,
            "framework": params.get("framework", ""),
            "status": "manual_review_required",
            "confidence": 0.0,
            "rationale": f"Stub evaluation for {control_id} on GCP. "
                         f"Evidence refs: {evidence_refs}. "
                         "Connect Security Command Center for automated evaluation.",
            "evidence_citations": [],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
