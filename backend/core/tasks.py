"""
Celery tasks for AI Continuous ATO platform.
"""

from celery import shared_task


@shared_task(bind=True, max_retries=3)
def run_compliance_check(self, system_id: str, baseline: str, providers: list[str]):
    """Kick off a full compliance check run via the LangGraph orchestrator."""
    from agents.orchestrator import run_compliance_check as orchestrate

    return orchestrate(system_id=system_id, baseline=baseline, providers=providers)
