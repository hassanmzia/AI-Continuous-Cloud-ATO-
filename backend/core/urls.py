"""Core app URL configuration."""

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"systems", views.SystemViewSet)
router.register(r"cloud-accounts", views.CloudAccountViewSet)
router.register(r"controls", views.ControlCatalogViewSet)
router.register(r"control-mappings", views.ControlMappingViewSet)
router.register(r"evidence", views.EvidenceArtifactViewSet)
router.register(r"runs", views.ComplianceRunViewSet)
router.register(r"assessments", views.ControlAssessmentViewSet)
router.register(r"drift-events", views.DriftEventViewSet)
router.register(r"stig-findings", views.StigFindingViewSet)
router.register(r"poam", views.POAMItemViewSet)
router.register(r"tickets", views.RemediationTicketViewSet)
router.register(r"approvals", views.ApprovalRequestViewSet)
router.register(r"audit-logs", views.AuditLogViewSet)

urlpatterns = [
    path("", include(router.urls)),
]
