"""
Django models for AI Continuous ATO platform.

Tables:
  System              — ATO boundary / system under assessment
  CloudAccount        — Cloud provider accounts within a system boundary
  ControlCatalog      — NIST 800-53 / FedRAMP / RMF control definitions
  ControlMapping      — Cross-framework mappings (NIST <-> FedRAMP <-> STIG)
  EvidenceArtifact    — Immutable evidence with hash + tags
  ComplianceRun       — Single assessment run (scheduled or ad-hoc)
  ControlAssessment   — Per-control pass/fail with confidence + citations
  DriftEvent          — Config/identity/network drift detections
  StigFinding         — STIG/SCAP finding records
  POAMItem            — Plan of Action & Milestones entries
  RemediationTicket   — External ticket references
  ApprovalRequest     — Human-in-the-loop approval queue
  AuditLog            — Immutable audit trail for all agent/MCP actions
"""

import uuid

from django.db import models


# ---------------------------------------------------------------------------
# Enums as TextChoices
# ---------------------------------------------------------------------------

class Provider(models.TextChoices):
    AWS = "aws", "AWS"
    AWS_GOV = "aws_gov", "AWS GovCloud"
    AZURE = "azure", "Azure"
    AZURE_GOV = "azure_gov", "Azure Government"
    GCP = "gcp", "GCP"
    GCP_GOV = "gcp_gov", "GCP Government"


class Framework(models.TextChoices):
    FEDRAMP = "fedramp", "FedRAMP"
    NIST_800_53 = "nist_800_53_r5", "NIST 800-53 Rev 5"
    RMF = "rmf", "RMF"
    STIG = "stig", "STIG"


class Baseline(models.TextChoices):
    FEDRAMP_LOW = "fedramp_low", "FedRAMP Low"
    FEDRAMP_MOD = "fedramp_mod", "FedRAMP Moderate"
    FEDRAMP_HIGH = "fedramp_high", "FedRAMP High"
    CUSTOM = "custom", "Custom"


class Severity(models.TextChoices):
    LOW = "low", "Low"
    MODERATE = "moderate", "Moderate"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class AssessmentStatus(models.TextChoices):
    PASS = "pass", "Pass"
    FAIL = "fail", "Fail"
    PARTIAL = "partial", "Partial"
    NOT_APPLICABLE = "not_applicable", "Not Applicable"
    MANUAL_REVIEW = "manual_review_required", "Manual Review Required"


class RunStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"
    AWAITING_APPROVAL = "awaiting_approval", "Awaiting Approval"


class ApprovalStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"


# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------

class BaseModel(models.Model):
    """Common fields for all models."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# ---------------------------------------------------------------------------
# System & Cloud Accounts
# ---------------------------------------------------------------------------

class System(BaseModel):
    """An ATO boundary / system under assessment."""
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    baseline = models.CharField(max_length=50, choices=Baseline.choices, default=Baseline.FEDRAMP_MOD)
    frameworks = models.JSONField(default=list, help_text="List of applicable frameworks")
    owner = models.CharField(max_length=255)
    environment = models.CharField(max_length=50, default="production")
    boundary_definition = models.JSONField(default=dict, help_text="Accounts, regions, tags, resource groups")
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class CloudAccount(BaseModel):
    """A cloud provider account/subscription/project within a system boundary."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="cloud_accounts")
    provider = models.CharField(max_length=20, choices=Provider.choices)
    account_id = models.CharField(max_length=255, help_text="AWS Account ID / Azure Subscription / GCP Project")
    alias = models.CharField(max_length=255, blank=True)
    regions = models.JSONField(default=list)
    tags = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ["system", "provider", "account_id"]
        ordering = ["provider", "account_id"]

    def __str__(self):
        return f"{self.provider}:{self.account_id}"


# ---------------------------------------------------------------------------
# Controls & Mappings
# ---------------------------------------------------------------------------

class ControlCatalog(BaseModel):
    """A control definition from any framework."""
    framework = models.CharField(max_length=50, choices=Framework.choices)
    control_id = models.CharField(max_length=50, db_index=True, help_text="e.g., AC-2, AU-6(1)")
    title = models.CharField(max_length=500)
    description = models.TextField()
    family = models.CharField(max_length=100, help_text="e.g., Access Control, Audit")
    baseline_impact = models.JSONField(default=list, help_text="['low','moderate','high'] for FedRAMP")
    parameters = models.JSONField(default=dict, blank=True)
    assessment_objective = models.TextField(blank=True)
    implementation_guidance = models.TextField(blank=True)

    class Meta:
        unique_together = ["framework", "control_id"]
        ordering = ["framework", "control_id"]

    def __str__(self):
        return f"{self.framework}:{self.control_id}"


class ControlMapping(BaseModel):
    """Cross-framework mapping (e.g., NIST AC-2 <-> STIG V-12345 via CCI)."""
    source_framework = models.CharField(max_length=50, choices=Framework.choices)
    source_control_id = models.CharField(max_length=50)
    target_framework = models.CharField(max_length=50, choices=Framework.choices)
    target_control_id = models.CharField(max_length=50)
    cci_id = models.CharField(max_length=50, blank=True, help_text="CCI Control Correlation Identifier")
    srg_id = models.CharField(max_length=50, blank=True, help_text="SRG Security Requirements Guide ID")
    mapping_confidence = models.FloatField(default=1.0, help_text="1.0 = exact, <1.0 = partial")

    class Meta:
        unique_together = ["source_framework", "source_control_id", "target_framework", "target_control_id"]
        ordering = ["source_framework", "source_control_id"]


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

class EvidenceArtifact(BaseModel):
    """Immutable evidence artifact stored in the vault."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="evidence_artifacts")
    artifact_type = models.CharField(max_length=100, help_text="config_snapshot, log_export, scan_report, ckl, etc.")
    storage_uri = models.TextField(help_text="S3/Blob/GCS URI in evidence vault")
    hash_sha256 = models.CharField(max_length=64, db_index=True)
    file_size_bytes = models.BigIntegerField(null=True, blank=True)
    provider = models.CharField(max_length=20, choices=Provider.choices, blank=True)
    environment = models.CharField(max_length=50, blank=True)
    control_ids = models.JSONField(default=list, help_text="Controls this evidence supports")
    frameworks = models.JSONField(default=list)
    tags = models.JSONField(default=dict)
    collected_at = models.DateTimeField(help_text="When the evidence was actually collected")
    retention_policy = models.CharField(max_length=50, default="standard")
    classification = models.CharField(max_length=50, default="unclassified")

    class Meta:
        ordering = ["-collected_at"]

    def __str__(self):
        return f"{self.artifact_type}:{self.hash_sha256[:12]}"


# ---------------------------------------------------------------------------
# Compliance Runs & Assessments
# ---------------------------------------------------------------------------

class ComplianceRun(BaseModel):
    """A single compliance assessment run (scheduled or ad-hoc)."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="compliance_runs")
    trigger = models.CharField(max_length=50, default="scheduled", help_text="scheduled | manual | drift_alert | api")
    question = models.TextField(blank=True, help_text="User query that triggered this run (if ad-hoc)")
    status = models.CharField(max_length=30, choices=RunStatus.choices, default=RunStatus.PENDING)
    providers_assessed = models.JSONField(default=list)
    frameworks_assessed = models.JSONField(default=list)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, help_text="High-level results: total/pass/fail/partial counts")
    overall_score = models.FloatField(null=True, blank=True, help_text="0-100 compliance score")
    agent_trace = models.JSONField(default=list, help_text="Ordered list of agent actions + tool calls for audit")

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Run {self.id} ({self.status})"


class ControlAssessment(BaseModel):
    """Per-control assessment result within a compliance run."""
    run = models.ForeignKey(ComplianceRun, on_delete=models.CASCADE, related_name="assessments")
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="control_assessments")
    framework = models.CharField(max_length=50, choices=Framework.choices)
    control_id = models.CharField(max_length=50, db_index=True)
    provider = models.CharField(max_length=20, choices=Provider.choices, blank=True)
    status = models.CharField(max_length=30, choices=AssessmentStatus.choices)
    confidence = models.FloatField(default=0.0, help_text="0.0-1.0 confidence in assessment")
    rationale = models.TextField(blank=True, help_text="LLM-generated rationale")
    evidence_artifacts = models.ManyToManyField(EvidenceArtifact, blank=True, related_name="assessments")
    evidence_sufficiency_score = models.FloatField(null=True, blank=True, help_text="Freshness + completeness + authority + consistency")
    contradictions_detected = models.JSONField(default=list, help_text="Policy vs reality contradictions")
    raw_findings = models.JSONField(default=dict)

    class Meta:
        ordering = ["framework", "control_id"]
        unique_together = ["run", "framework", "control_id", "provider"]


# ---------------------------------------------------------------------------
# Drift Detection
# ---------------------------------------------------------------------------

class DriftEvent(BaseModel):
    """A detected configuration/identity/network drift event."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="drift_events")
    run = models.ForeignKey(ComplianceRun, on_delete=models.SET_NULL, null=True, blank=True, related_name="drift_events")
    provider = models.CharField(max_length=20, choices=Provider.choices)
    resource_type = models.CharField(max_length=100)
    resource_id = models.CharField(max_length=500)
    field_path = models.CharField(max_length=500, help_text="JSON path of changed field")
    baseline_value = models.JSONField(null=True, blank=True)
    current_value = models.JSONField(null=True, blank=True)
    changed_by = models.CharField(max_length=255, blank=True)
    changed_at = models.DateTimeField(null=True, blank=True)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.MODERATE)
    affected_controls = models.JSONField(default=list)
    baseline_artifact = models.ForeignKey(
        EvidenceArtifact, on_delete=models.SET_NULL, null=True, blank=True, related_name="drift_baselines"
    )
    current_artifact = models.ForeignKey(
        EvidenceArtifact, on_delete=models.SET_NULL, null=True, blank=True, related_name="drift_currents"
    )
    resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]


# ---------------------------------------------------------------------------
# STIG Findings
# ---------------------------------------------------------------------------

class StigFinding(BaseModel):
    """A STIG/SCAP finding record from CKL ingestion or SCAP scan."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="stig_findings")
    run = models.ForeignKey(ComplianceRun, on_delete=models.SET_NULL, null=True, blank=True, related_name="stig_findings")
    asset_id = models.CharField(max_length=255, help_text="Host or application being assessed")
    stig_name = models.CharField(max_length=255)
    stig_version = models.CharField(max_length=50, blank=True)
    vuln_id = models.CharField(max_length=50, db_index=True)
    rule_id = models.CharField(max_length=50, db_index=True)
    stig_id = models.CharField(max_length=50, blank=True)
    severity = models.CharField(max_length=20, help_text="CAT_I, CAT_II, CAT_III")
    status = models.CharField(max_length=30, help_text="Not_A_Finding, Open, Not_Applicable, Not_Reviewed")
    finding_details = models.TextField(blank=True)
    comments = models.TextField(blank=True)
    mapped_nist_controls = models.JSONField(default=list, help_text="NIST 800-53 controls via CCI crosswalk")
    evidence_artifact = models.ForeignKey(
        EvidenceArtifact, on_delete=models.SET_NULL, null=True, blank=True, related_name="stig_findings"
    )

    class Meta:
        ordering = ["stig_name", "vuln_id"]


# ---------------------------------------------------------------------------
# POA&M
# ---------------------------------------------------------------------------

class POAMItem(BaseModel):
    """Plan of Action & Milestones entry for a failed/at-risk control."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="poam_items")
    run = models.ForeignKey(ComplianceRun, on_delete=models.SET_NULL, null=True, blank=True, related_name="poam_items")
    framework = models.CharField(max_length=50, choices=Framework.choices)
    control_id = models.CharField(max_length=50, db_index=True)
    weakness = models.TextField()
    severity = models.CharField(max_length=20, choices=Severity.choices)
    status = models.CharField(max_length=30, default="open", help_text="open | in_progress | completed | risk_accepted")
    owner = models.CharField(max_length=255)
    due_date = models.DateField()
    milestones = models.JSONField(default=list, help_text="[{description, target_date, status}]")
    evidence_artifacts = models.ManyToManyField(EvidenceArtifact, blank=True, related_name="poam_items")
    risk_accepted = models.BooleanField(default=False)
    risk_accepted_by = models.CharField(max_length=255, blank=True)
    risk_acceptance_justification = models.TextField(blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-severity", "due_date"]


# ---------------------------------------------------------------------------
# Remediation Tickets
# ---------------------------------------------------------------------------

class RemediationTicket(BaseModel):
    """External ticket reference (Jira/ServiceNow/GitHub Issues)."""
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="remediation_tickets")
    poam_item = models.ForeignKey(POAMItem, on_delete=models.SET_NULL, null=True, blank=True, related_name="tickets")
    ticket_system = models.CharField(max_length=30, help_text="jira | servicenow | github")
    ticket_id = models.CharField(max_length=100)
    ticket_url = models.URLField(max_length=500, blank=True)
    title = models.CharField(max_length=500)
    status = models.CharField(max_length=50, default="open")
    priority = models.CharField(max_length=20, blank=True)
    assignee = models.CharField(max_length=255, blank=True)
    linked_controls = models.JSONField(default=list)

    class Meta:
        ordering = ["-created_at"]


# ---------------------------------------------------------------------------
# Approval Queue (Human-in-the-loop)
# ---------------------------------------------------------------------------

class ApprovalRequest(BaseModel):
    """Human-in-the-loop approval request for high-risk remediation actions."""
    run = models.ForeignKey(ComplianceRun, on_delete=models.CASCADE, related_name="approval_requests")
    system = models.ForeignKey(System, on_delete=models.CASCADE, related_name="approval_requests")
    action_type = models.CharField(max_length=50, help_text="create_ticket | create_pr | create_poam | deploy")
    action_payload = models.JSONField(help_text="Proposed action details for reviewer")
    affected_controls = models.JSONField(default=list)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=ApprovalStatus.choices, default=ApprovalStatus.PENDING)
    requested_by_agent = models.CharField(max_length=100, help_text="Agent that requested approval")
    reviewed_by = models.CharField(max_length=255, blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]


# ---------------------------------------------------------------------------
# Audit Log (Immutable)
# ---------------------------------------------------------------------------

class AuditLog(BaseModel):
    """Immutable audit trail for all agent actions, MCP tool calls, and state transitions."""
    run = models.ForeignKey(ComplianceRun, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    system = models.ForeignKey(System, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_logs")
    agent_id = models.CharField(max_length=100, blank=True, help_text="Which agent performed this action")
    action = models.CharField(max_length=200, db_index=True, help_text="e.g., mcp.call.get_config_snapshot")
    target = models.CharField(max_length=500, blank=True, help_text="Resource/control/artifact targeted")
    input_summary = models.JSONField(default=dict, help_text="Summarized input (never raw secrets)")
    output_summary = models.JSONField(default=dict, help_text="Summarized output")
    output_hash = models.CharField(max_length=64, blank=True, help_text="SHA-256 of full output for integrity")
    duration_ms = models.IntegerField(null=True, blank=True)
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    correlation_id = models.CharField(max_length=100, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        # Prevent updates/deletes in application code — enforce via DB triggers or WORM policy
