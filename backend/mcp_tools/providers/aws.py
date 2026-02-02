"""
AWS + AWS GovCloud MCP Provider Implementation.

Translates canonical MCP compliance_core tool calls into AWS API calls.
Supports both commercial (aws) and GovCloud (aws_gov) partitions.

AWS Services used:
  - Config: Configuration snapshots, compliance rules
  - CloudTrail: Audit logs
  - Security Hub: Security findings, posture
  - IAM: Identity and access management config
  - SSM: Systems Manager inventory, patch compliance
  - EC2/S3/EKS/RDS/KMS: Resource-specific config
  - GuardDuty: Threat detection findings
  - Inspector: Vulnerability findings
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Partition endpoints
AWS_PARTITIONS = {
    "aws": {
        "partition": "aws",
        "sts_endpoint": "https://sts.amazonaws.com",
        "config_endpoint": None,  # Uses default regional
    },
    "aws_gov": {
        "partition": "aws-us-gov",
        "sts_endpoint": "https://sts.us-gov-west-1.amazonaws.com",
        "config_endpoint": None,
    },
}


class AWSProvider:
    """
    AWS MCP provider — implements canonical compliance_core methods
    against AWS APIs (commercial + GovCloud).
    """

    def __init__(self, provider_type: str = "aws", credentials: Optional[Dict] = None):
        """
        Args:
            provider_type: 'aws' or 'aws_gov'
            credentials: AWS credentials dict or None for default chain
        """
        self.provider_type = provider_type
        self.partition_config = AWS_PARTITIONS[provider_type]
        self._credentials = credentials
        self._clients: Dict[str, Any] = {}
        logger.info(f"AWS MCP Provider initialized: {provider_type}")

    def _get_client(self, service: str, region: str = "us-east-1"):
        """Get or create a boto3 client for the given service and region."""
        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed — returning stub client")
            return None

        key = f"{service}:{region}"
        if key not in self._clients:
            session_kwargs = {}
            if self._credentials:
                session_kwargs.update(self._credentials)
            session = boto3.Session(**session_kwargs)
            self._clients[key] = session.client(service, region_name=region)
        return self._clients[key]

    # ----- compliance_core.get_asset_inventory -----
    def get_asset_inventory(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Enumerate assets within ATO boundary using AWS Config and resource APIs."""
        scope = params.get("scope", {})
        regions = scope.get("regions", ["us-east-1"])
        tags = scope.get("tags", {})

        assets: List[Dict[str, Any]] = []
        for region in regions:
            config_client = self._get_client("config", region)
            if config_client is None:
                # Stub response when boto3 unavailable
                assets.append({
                    "asset_id": f"stub-{region}",
                    "resource_type": "stub",
                    "name": "Stub resource (boto3 not available)",
                    "region": region,
                    "tags": tags,
                    "provider_native_id": "N/A",
                    "status": "stub",
                })
                continue

            try:
                paginator = config_client.get_paginator("list_discovered_resources")
                for resource_type in [
                    "AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::IAM::Role",
                    "AWS::RDS::DBInstance", "AWS::EKS::Cluster", "AWS::KMS::Key",
                    "AWS::Lambda::Function", "AWS::ElasticLoadBalancingV2::LoadBalancer",
                ]:
                    for page in paginator.paginate(resourceType=resource_type):
                        for resource in page.get("resourceIdentifiers", []):
                            assets.append({
                                "asset_id": resource.get("resourceId", ""),
                                "resource_type": resource.get("resourceType", ""),
                                "name": resource.get("resourceName", ""),
                                "region": region,
                                "tags": tags,
                                "provider_native_id": resource.get("resourceId", ""),
                                "status": "active",
                            })
            except Exception as e:
                logger.error(f"AWS asset inventory failed for {region}: {e}")
                assets.append({
                    "asset_id": f"error-{region}",
                    "resource_type": "error",
                    "name": str(e),
                    "region": region,
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
        """Fetch current configuration state for a resource class."""
        resource_type = params.get("resource_type", "")
        scope = params.get("scope", {})
        regions = scope.get("regions", ["us-east-1"])

        # Map canonical resource types to AWS resource type identifiers
        aws_type_map = {
            "iam": ["AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::User", "AWS::IAM::Group"],
            "storage": ["AWS::S3::Bucket"],
            "network": ["AWS::EC2::VPC", "AWS::EC2::SecurityGroup", "AWS::EC2::Subnet"],
            "compute": ["AWS::EC2::Instance", "AWS::Lambda::Function"],
            "kubernetes": ["AWS::EKS::Cluster"],
            "database": ["AWS::RDS::DBInstance", "AWS::DynamoDB::Table"],
            "encryption": ["AWS::KMS::Key"],
            "logging": ["AWS::CloudTrail::Trail", "AWS::Logs::LogGroup"],
        }

        aws_types = aws_type_map.get(resource_type, [])
        resources: List[Dict[str, Any]] = []

        for region in regions:
            config_client = self._get_client("config", region)
            if config_client is None:
                resources.append({
                    "resource_id": "stub",
                    "config": {"stub": True, "resource_type": resource_type},
                    "last_modified": datetime.now(timezone.utc).isoformat(),
                    "provider_native_id": "N/A",
                })
                continue

            for aws_type in aws_types:
                try:
                    response = config_client.get_discovered_resource_counts(
                        resourceTypes=[aws_type]
                    )
                    # In production: use get_resource_config_history or
                    # batch_get_resource_config for actual config data
                    resources.append({
                        "resource_id": aws_type,
                        "config": {"type": aws_type, "count": response.get("totalDiscoveredResources", 0)},
                        "last_modified": datetime.now(timezone.utc).isoformat(),
                        "provider_native_id": aws_type,
                    })
                except Exception as e:
                    logger.error(f"AWS config snapshot failed for {aws_type} in {region}: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "resource_type": resource_type,
            "resources": resources,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ----- compliance_core.query_audit_logs -----
    def query_audit_logs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query CloudTrail for audit events."""
        query = params.get("query", {})
        time_range = params.get("time_range", {})
        scope = params.get("scope", {})
        regions = scope.get("regions", ["us-east-1"])

        events: List[Dict[str, Any]] = []
        for region in regions:
            ct_client = self._get_client("cloudtrail", region)
            if ct_client is None:
                events.append({
                    "event_id": "stub",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "actor": "stub",
                    "action": "stub",
                    "resource": "stub",
                    "result": "stub",
                })
                continue

            try:
                lookup_attrs = []
                if query.get("event_types"):
                    for et in query["event_types"]:
                        lookup_attrs.append({"AttributeKey": "EventName", "AttributeValue": et})

                ct_params = {}
                if time_range.get("start"):
                    ct_params["StartTime"] = time_range["start"]
                if time_range.get("end"):
                    ct_params["EndTime"] = time_range["end"]
                if lookup_attrs:
                    ct_params["LookupAttributes"] = lookup_attrs[:1]  # CloudTrail only supports 1
                ct_params["MaxResults"] = min(params.get("max_results", 50), 50)

                response = ct_client.lookup_events(**ct_params)
                for event in response.get("Events", []):
                    events.append({
                        "event_id": event.get("EventId", ""),
                        "timestamp": event.get("EventTime", "").isoformat() if hasattr(event.get("EventTime", ""), "isoformat") else str(event.get("EventTime", "")),
                        "actor": event.get("Username", ""),
                        "action": event.get("EventName", ""),
                        "resource": str(event.get("Resources", [])),
                        "result": "Success",
                        "source_ip": event.get("SourceIPAddress", ""),
                    })
            except Exception as e:
                logger.error(f"AWS CloudTrail query failed for {region}: {e}")

        return {
            "provider": self.provider_type,
            "system_id": params.get("system_id", ""),
            "events": events,
            "total_count": len(events),
            "truncated": False,
        }

    # ----- compliance_core.evaluate_control_rule -----
    def evaluate_control_rule(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a control rule using AWS Security Hub findings + Config rules.
        In production, this correlates evidence artifacts with specific checks.
        """
        control_id = params.get("control_id", "")
        evidence_refs = params.get("evidence_refs", [])

        # Stub: In production, pull Security Hub findings for this control
        return {
            "control_id": control_id,
            "framework": params.get("framework", ""),
            "status": "manual_review_required",
            "confidence": 0.0,
            "rationale": f"Stub evaluation for {control_id} on AWS. "
                         f"Evidence refs: {evidence_refs}. "
                         "Connect Security Hub / Config Rules for automated evaluation.",
            "evidence_citations": [],
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }
