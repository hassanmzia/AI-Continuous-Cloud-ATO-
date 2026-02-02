"""REST API views for AI Continuous ATO platform."""

from datetime import datetime, timezone

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import (
    ApprovalRequest,
    AuditLog,
    CloudAccount,
    ComplianceRun,
    ControlAssessment,
    ControlCatalog,
    ControlMapping,
    DriftEvent,
    EvidenceArtifact,
    POAMItem,
    RemediationTicket,
    StigFinding,
    System,
)
from .serializers import (
    ApprovalActionSerializer,
    ApprovalRequestSerializer,
    AuditLogSerializer,
    CloudAccountSerializer,
    ComplianceCheckRequestSerializer,
    ComplianceRunDetailSerializer,
    ComplianceRunSerializer,
    ControlAssessmentSerializer,
    ControlCatalogSerializer,
    ControlMappingSerializer,
    DriftEventSerializer,
    EvidenceArtifactSerializer,
    POAMItemSerializer,
    RemediationTicketSerializer,
    StigFindingSerializer,
    SystemCreateSerializer,
    SystemSerializer,
)


class SystemViewSet(viewsets.ModelViewSet):
    """CRUD for ATO systems/boundaries."""
    queryset = System.objects.all()
    filterset_fields = ["is_active", "baseline", "environment"]
    search_fields = ["name", "description", "owner"]
    ordering_fields = ["name", "created_at"]

    def get_serializer_class(self):
        if self.action in ("create", "update", "partial_update"):
            return SystemCreateSerializer
        return SystemSerializer


class CloudAccountViewSet(viewsets.ModelViewSet):
    """CRUD for cloud accounts within system boundaries."""
    queryset = CloudAccount.objects.all()
    serializer_class = CloudAccountSerializer
    filterset_fields = ["system", "provider", "is_active"]


class ControlCatalogViewSet(viewsets.ModelViewSet):
    """CRUD for compliance control definitions."""
    queryset = ControlCatalog.objects.all()
    serializer_class = ControlCatalogSerializer
    filterset_fields = ["framework", "family"]
    search_fields = ["control_id", "title", "description"]


class ControlMappingViewSet(viewsets.ModelViewSet):
    """CRUD for cross-framework control mappings."""
    queryset = ControlMapping.objects.all()
    serializer_class = ControlMappingSerializer
    filterset_fields = ["source_framework", "target_framework"]


class EvidenceArtifactViewSet(viewsets.ModelViewSet):
    """CRUD for evidence artifacts."""
    queryset = EvidenceArtifact.objects.all()
    serializer_class = EvidenceArtifactSerializer
    filterset_fields = ["system", "artifact_type", "provider", "environment"]
    search_fields = ["hash_sha256"]
    ordering_fields = ["collected_at", "created_at"]


class ComplianceRunViewSet(viewsets.ModelViewSet):
    """
    Compliance run management.

    Supports:
    - List/retrieve runs
    - Trigger new compliance checks via POST /api/runs/trigger/
    - Get detailed results via GET /api/runs/{id}/
    """
    queryset = ComplianceRun.objects.all()
    filterset_fields = ["system", "status", "trigger"]
    ordering_fields = ["created_at", "overall_score"]

    def get_serializer_class(self):
        if self.action == "retrieve":
            return ComplianceRunDetailSerializer
        return ComplianceRunSerializer

    @action(detail=False, methods=["post"], url_path="trigger")
    def trigger_compliance_check(self, request):
        """
        Trigger a new compliance check.

        POST /api/runs/trigger/
        {
            "system_id": "uuid",
            "question": "Are we still FedRAMP compliant today?",
            "providers": ["aws", "azure"],
            "baseline": "fedramp_mod"
        }
        """
        serializer = ComplianceCheckRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Create the run record
        run = ComplianceRun.objects.create(
            system_id=serializer.validated_data.get("system_id"),
            trigger="api",
            question=serializer.validated_data.get("question", ""),
            status="pending",
            providers_assessed=serializer.validated_data.get("providers", []),
            frameworks_assessed=serializer.validated_data.get("frameworks", []),
        )

        # In production: dispatch to Celery worker
        # from agents.orchestrator import run_compliance_check
        # run_compliance_check.delay(...)

        return Response(
            {
                "run_id": str(run.id),
                "status": "pending",
                "message": "Compliance check queued. Poll GET /api/runs/{run_id}/ for results.",
            },
            status=status.HTTP_202_ACCEPTED,
        )


class ControlAssessmentViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only access to control assessment results."""
    queryset = ControlAssessment.objects.all()
    serializer_class = ControlAssessmentSerializer
    filterset_fields = ["run", "system", "framework", "status", "provider"]
    search_fields = ["control_id", "rationale"]
    ordering_fields = ["confidence", "created_at"]


class DriftEventViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only access to drift events."""
    queryset = DriftEvent.objects.all()
    serializer_class = DriftEventSerializer
    filterset_fields = ["system", "provider", "severity", "resolved"]
    ordering_fields = ["created_at", "severity"]


class StigFindingViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only access to STIG findings."""
    queryset = StigFinding.objects.all()
    serializer_class = StigFindingSerializer
    filterset_fields = ["system", "severity", "status", "stig_name"]
    search_fields = ["vuln_id", "rule_id", "finding_details"]


class POAMItemViewSet(viewsets.ModelViewSet):
    """CRUD for POA&M items."""
    queryset = POAMItem.objects.all()
    serializer_class = POAMItemSerializer
    filterset_fields = ["system", "framework", "severity", "status"]
    search_fields = ["control_id", "weakness"]
    ordering_fields = ["due_date", "severity", "created_at"]


class RemediationTicketViewSet(viewsets.ModelViewSet):
    """CRUD for remediation tickets."""
    queryset = RemediationTicket.objects.all()
    serializer_class = RemediationTicketSerializer
    filterset_fields = ["system", "ticket_system", "status"]


class ApprovalRequestViewSet(viewsets.ModelViewSet):
    """
    Approval queue management.

    Supports:
    - List pending approvals
    - Approve/reject via POST /api/approvals/{id}/review/
    """
    queryset = ApprovalRequest.objects.all()
    serializer_class = ApprovalRequestSerializer
    filterset_fields = ["system", "status", "severity"]
    ordering_fields = ["created_at", "severity"]

    @action(detail=True, methods=["post"], url_path="review")
    def review(self, request, pk=None):
        """
        Approve or reject an approval request.

        POST /api/approvals/{id}/review/
        {"status": "approved", "reviewed_by": "admin@example.com", "review_notes": "..."}
        """
        approval = self.get_object()
        serializer = ApprovalActionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        approval.status = serializer.validated_data["status"]
        approval.reviewed_by = serializer.validated_data["reviewed_by"]
        approval.review_notes = serializer.validated_data.get("review_notes", "")
        approval.reviewed_at = datetime.now(timezone.utc)
        approval.save()

        return Response(
            ApprovalRequestSerializer(approval).data,
            status=status.HTTP_200_OK,
        )


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only access to audit logs (immutable)."""
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    filterset_fields = ["run", "system", "agent_id", "success"]
    search_fields = ["action", "target"]
    ordering_fields = ["created_at"]
