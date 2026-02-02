"""REST API serializers for AI Continuous ATO platform."""

from rest_framework import serializers
from .models import (
    System, CloudAccount, ControlCatalog, ControlMapping,
    EvidenceArtifact, ComplianceRun, ControlAssessment, DriftEvent,
    StigFinding, POAMItem, RemediationTicket, ApprovalRequest, AuditLog,
)


class CloudAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = CloudAccount
        fields = "__all__"


class SystemSerializer(serializers.ModelSerializer):
    cloud_accounts = CloudAccountSerializer(many=True, read_only=True)

    class Meta:
        model = System
        fields = "__all__"


class SystemCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = System
        fields = "__all__"


class ControlCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ControlCatalog
        fields = "__all__"


class ControlMappingSerializer(serializers.ModelSerializer):
    class Meta:
        model = ControlMapping
        fields = "__all__"


class EvidenceArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = EvidenceArtifact
        fields = "__all__"


class ControlAssessmentSerializer(serializers.ModelSerializer):
    evidence_artifacts = EvidenceArtifactSerializer(many=True, read_only=True)

    class Meta:
        model = ControlAssessment
        fields = "__all__"


class ComplianceRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceRun
        fields = "__all__"


class ComplianceRunDetailSerializer(serializers.ModelSerializer):
    assessments = ControlAssessmentSerializer(many=True, read_only=True)

    class Meta:
        model = ComplianceRun
        fields = "__all__"


class DriftEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = DriftEvent
        fields = "__all__"


class StigFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = StigFinding
        fields = "__all__"


class POAMItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = POAMItem
        fields = "__all__"


class RemediationTicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemediationTicket
        fields = "__all__"


class ApprovalRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ApprovalRequest
        fields = "__all__"


class ApprovalActionSerializer(serializers.Serializer):
    """Serializer for approval/rejection actions."""
    status = serializers.ChoiceField(choices=["approved", "rejected"])
    reviewed_by = serializers.CharField(max_length=255)
    review_notes = serializers.CharField(required=False, allow_blank=True)


class AuditLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditLog
        fields = "__all__"


class ComplianceCheckRequestSerializer(serializers.Serializer):
    """Serializer for triggering a new compliance check."""
    system_id = serializers.UUIDField(required=False)
    system_name = serializers.CharField(required=False, allow_blank=True)
    question = serializers.CharField(
        default="Are we still compliant today?",
        required=False,
    )
    providers = serializers.ListField(
        child=serializers.CharField(),
        required=False,
    )
    baseline = serializers.ChoiceField(
        choices=["fedramp_low", "fedramp_mod", "fedramp_high", "custom"],
        default="fedramp_mod",
        required=False,
    )
    frameworks = serializers.ListField(
        child=serializers.CharField(),
        required=False,
    )
