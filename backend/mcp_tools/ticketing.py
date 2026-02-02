"""
Ticketing MCP Tools — Jira, ServiceNow, GitHub Issues integration.

Creates, updates, and queries remediation tickets linked to compliance findings.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TicketingTools:
    """MCP tool implementations for external ticketing systems."""

    def __init__(self, configs: Optional[Dict[str, Any]] = None):
        """
        Args:
            configs: Per-system configuration, e.g.:
                {
                    "jira": {"url": "...", "token": "...", "project": "..."},
                    "servicenow": {"instance": "...", "token": "..."},
                    "github": {"repo": "...", "token": "..."},
                }
        """
        self.configs = configs or {}

    def create_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a remediation ticket in the specified system."""
        system = params.get("system", "")
        title = params.get("title", "")
        description = params.get("description", "")
        priority = params.get("priority", "medium")
        assignee = params.get("assignee", "")
        labels = params.get("labels", [])
        links = params.get("links", [])
        due_date = params.get("due_date", "")

        handler = {
            "jira": self._create_jira_ticket,
            "servicenow": self._create_servicenow_ticket,
            "github": self._create_github_ticket,
        }.get(system)

        if handler:
            return handler(params)

        # Stub response for unconfigured systems
        ticket_id = f"STUB-{str(uuid.uuid4())[:8].upper()}"
        return {
            "ticket_id": ticket_id,
            "ticket_url": f"https://{system}.example.com/ticket/{ticket_id}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
        }

    def update_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing ticket."""
        system = params.get("system", "")
        ticket_id = params.get("ticket_id", "")

        # Stub: In production, call the appropriate API
        return {
            "ticket_id": ticket_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "status": params.get("status", "updated"),
        }

    def query_tickets(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Query tickets by filters."""
        system = params.get("system", "")
        filters = params.get("filters", {})

        # Stub: In production, query the appropriate API
        return {
            "tickets": [],
            "total_count": 0,
        }

    # --- Provider-specific implementations ---

    def _create_jira_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Jira ticket."""
        config = self.configs.get("jira", {})
        if not config:
            return self._stub_ticket("jira", params)

        try:
            import httpx

            jira_url = config["url"]
            response = httpx.post(
                f"{jira_url}/rest/api/2/issue",
                headers={
                    "Authorization": f"Bearer {config['token']}",
                    "Content-Type": "application/json",
                },
                json={
                    "fields": {
                        "project": {"key": params.get("project_key", config.get("project", ""))},
                        "summary": params.get("title", ""),
                        "description": params.get("description", ""),
                        "priority": {"name": params.get("priority", "Medium").title()},
                        "labels": params.get("labels", []),
                        "issuetype": {"name": "Task"},
                    }
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "ticket_id": data.get("key", ""),
                "ticket_url": f"{jira_url}/browse/{data.get('key', '')}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "open",
            }
        except Exception as e:
            logger.error(f"Jira ticket creation failed: {e}")
            return self._stub_ticket("jira", params)

    def _create_servicenow_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a ServiceNow incident/task."""
        config = self.configs.get("servicenow", {})
        if not config:
            return self._stub_ticket("servicenow", params)

        try:
            import httpx

            instance = config["instance"]
            response = httpx.post(
                f"https://{instance}.service-now.com/api/now/table/incident",
                headers={
                    "Authorization": f"Bearer {config['token']}",
                    "Content-Type": "application/json",
                },
                json={
                    "short_description": params.get("title", ""),
                    "description": params.get("description", ""),
                    "priority": {"low": "4", "medium": "3", "high": "2", "critical": "1"}.get(
                        params.get("priority", "medium"), "3"
                    ),
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json().get("result", {})
            return {
                "ticket_id": data.get("number", ""),
                "ticket_url": f"https://{instance}.service-now.com/nav_to.do?uri=incident.do?sys_id={data.get('sys_id', '')}",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "open",
            }
        except Exception as e:
            logger.error(f"ServiceNow ticket creation failed: {e}")
            return self._stub_ticket("servicenow", params)

    def _create_github_ticket(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a GitHub issue."""
        config = self.configs.get("github", {})
        if not config:
            return self._stub_ticket("github", params)

        try:
            import httpx

            repo = config["repo"]
            response = httpx.post(
                f"https://api.github.com/repos/{repo}/issues",
                headers={
                    "Authorization": f"Bearer {config['token']}",
                    "Accept": "application/vnd.github+json",
                },
                json={
                    "title": params.get("title", ""),
                    "body": params.get("description", ""),
                    "labels": params.get("labels", []),
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
            return {
                "ticket_id": str(data.get("number", "")),
                "ticket_url": data.get("html_url", ""),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "status": "open",
            }
        except Exception as e:
            logger.error(f"GitHub issue creation failed: {e}")
            return self._stub_ticket("github", params)

    @staticmethod
    def _stub_ticket(system: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Return a stub ticket response."""
        ticket_id = f"STUB-{str(uuid.uuid4())[:8].upper()}"
        return {
            "ticket_id": ticket_id,
            "ticket_url": f"https://{system}.example.com/ticket/{ticket_id}",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "status": "open",
        }
