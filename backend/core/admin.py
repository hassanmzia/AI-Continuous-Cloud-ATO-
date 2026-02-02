"""Django admin configuration for AI Continuous ATO platform."""

from django.contrib import admin
from .models import (
    System, CloudAccount, ControlCatalog, ControlMapping,
    EvidenceArtifact, ComplianceRun, ControlAssessment, DriftEvent,
    StigFinding, POAMItem, RemediationTicket, ApprovalRequest, AuditLog,
)


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    list_display = ["name", "baseline", "environment", "owner", "is_active", "created_at"]
    list_filter = ["baseline", "environment", "is_active"]
    search_fields = ["name", "description", "owner"]


@admin.register(CloudAccount)
class CloudAccountAdmin(admin.ModelAdmin):
    list_display = ["system", "provider", "account_id", "alias", "is_active"]
    list_filter = ["provider", "is_active"]


@admin.register(ControlCatalog)
class ControlCatalogAdmin(admin.ModelAdmin):
    list_display = ["framework", "control_id", "title", "family"]
    list_filter = ["framework", "family"]
    search_fields = ["control_id", "title"]


@admin.register(ControlMapping)
class ControlMappingAdmin(admin.ModelAdmin):
    list_display = ["source_framework", "source_control_id", "target_framework", "target_control_id", "cci_id"]
    list_filter = ["source_framework", "target_framework"]


@admin.register(EvidenceArtifact)
class EvidenceArtifactAdmin(admin.ModelAdmin):
    list_display = ["system", "artifact_type", "provider", "hash_sha256", "collected_at"]
    list_filter = ["artifact_type", "provider"]


@admin.register(ComplianceRun)
class ComplianceRunAdmin(admin.ModelAdmin):
    list_display = ["id", "system", "trigger", "status", "overall_score", "created_at"]
    list_filter = ["status", "trigger"]


@admin.register(ControlAssessment)
class ControlAssessmentAdmin(admin.ModelAdmin):
    list_display = ["run", "control_id", "framework", "status", "confidence"]
    list_filter = ["framework", "status"]


@admin.register(DriftEvent)
class DriftEventAdmin(admin.ModelAdmin):
    list_display = ["system", "provider", "resource_type", "resource_id", "severity", "resolved"]
    list_filter = ["provider", "severity", "resolved"]


@admin.register(StigFinding)
class StigFindingAdmin(admin.ModelAdmin):
    list_display = ["system", "vuln_id", "severity", "status", "stig_name", "asset_id"]
    list_filter = ["severity", "status", "stig_name"]


@admin.register(POAMItem)
class POAMItemAdmin(admin.ModelAdmin):
    list_display = ["system", "control_id", "framework", "severity", "status", "owner", "due_date"]
    list_filter = ["framework", "severity", "status"]


@admin.register(RemediationTicket)
class RemediationTicketAdmin(admin.ModelAdmin):
    list_display = ["system", "ticket_system", "ticket_id", "title", "status"]
    list_filter = ["ticket_system", "status"]


@admin.register(ApprovalRequest)
class ApprovalRequestAdmin(admin.ModelAdmin):
    list_display = ["system", "action_type", "severity", "status", "requested_by_agent", "reviewed_by"]
    list_filter = ["status", "severity"]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ["run", "agent_id", "action", "success", "duration_ms", "created_at"]
    list_filter = ["agent_id", "success"]
    search_fields = ["action", "target"]
