"""
Indexing Pipeline — Chunking, metadata tagging, and embedding for compliance knowledge.

Processes and indexes:
  - NIST 800-53 control catalog (descriptions, assessment objectives, guidance)
  - FedRAMP baselines and implementation guidance
  - SSP implementation statements
  - STIG benchmarks (check content, fix text, CCI mappings)
  - Organizational policies and procedures
  - Evidence artifact metadata and summaries
"""

import logging
from typing import Any, Dict, List, Optional

from langchain.schema import Document

logger = logging.getLogger(__name__)

# Chunking configuration per document type
CHUNK_CONFIGS = {
    "nist_control": {"chunk_size": 1000, "chunk_overlap": 200, "separator": "\n\n"},
    "stig_check": {"chunk_size": 800, "chunk_overlap": 150, "separator": "\n"},
    "ssp_statement": {"chunk_size": 1500, "chunk_overlap": 300, "separator": "\n\n"},
    "policy_doc": {"chunk_size": 1200, "chunk_overlap": 250, "separator": "\n\n"},
    "evidence_summary": {"chunk_size": 600, "chunk_overlap": 100, "separator": "\n"},
    "default": {"chunk_size": 1000, "chunk_overlap": 200, "separator": "\n\n"},
}


class ComplianceIndexer:
    """
    Indexing pipeline for compliance knowledge base.

    Ingests compliance documents, chunks them with appropriate strategies,
    attaches rich metadata (framework, control_id, provider, dates, etc.),
    generates embeddings, and stores in the vector database.
    """

    def __init__(self, vector_store_manager):
        self.vector_store = vector_store_manager

    def index_nist_controls(self, controls: List[Dict[str, Any]]) -> int:
        """
        Index NIST 800-53 Rev 5 controls into the vector store.

        Each control becomes one or more documents with metadata:
          - framework, control_id, family, baseline_impact
          - Separate chunks for description, assessment_objective, implementation_guidance
        """
        documents = []
        for ctrl in controls:
            base_metadata = {
                "doc_type": "nist_control",
                "framework": ctrl.get("framework", "nist_800_53_r5"),
                "control_id": ctrl.get("control_id", ""),
                "family": ctrl.get("family", ""),
                "baseline_impact": ",".join(ctrl.get("baseline_impact", [])),
            }

            # Description chunk
            if ctrl.get("description"):
                documents.append(Document(
                    page_content=f"Control {ctrl['control_id']}: {ctrl.get('title', '')}\n\n{ctrl['description']}",
                    metadata={**base_metadata, "section": "description"},
                ))

            # Assessment objective chunk
            if ctrl.get("assessment_objective"):
                documents.append(Document(
                    page_content=f"Assessment Objective for {ctrl['control_id']}:\n\n{ctrl['assessment_objective']}",
                    metadata={**base_metadata, "section": "assessment_objective"},
                ))

            # Implementation guidance chunk
            if ctrl.get("implementation_guidance"):
                documents.append(Document(
                    page_content=f"Implementation Guidance for {ctrl['control_id']}:\n\n{ctrl['implementation_guidance']}",
                    metadata={**base_metadata, "section": "implementation_guidance"},
                ))

        if documents:
            chunks = self._chunk_documents(documents, "nist_control")
            ids = self.vector_store.add_documents(chunks)
            logger.info(f"Indexed {len(ids)} NIST control chunks from {len(controls)} controls")
            return len(ids)
        return 0

    def index_stig_benchmarks(self, benchmarks: List[Dict[str, Any]]) -> int:
        """
        Index STIG benchmark checks into the vector store.

        Each STIG check becomes a document with metadata:
          - stig_name, vuln_id, rule_id, severity, mapped CCI/NIST controls
        """
        documents = []
        for check in benchmarks:
            metadata = {
                "doc_type": "stig_check",
                "stig_name": check.get("stig_name", ""),
                "vuln_id": check.get("vuln_id", ""),
                "rule_id": check.get("rule_id", ""),
                "severity": check.get("severity", ""),
                "cci_ids": ",".join(check.get("cci_ids", [])),
                "nist_controls": ",".join(check.get("nist_controls", [])),
            }

            content_parts = [f"STIG Check {check.get('vuln_id', '')} ({check.get('severity', '')})"]
            if check.get("title"):
                content_parts.append(f"Title: {check['title']}")
            if check.get("check_content"):
                content_parts.append(f"Check: {check['check_content']}")
            if check.get("fix_text"):
                content_parts.append(f"Fix: {check['fix_text']}")

            documents.append(Document(
                page_content="\n\n".join(content_parts),
                metadata=metadata,
            ))

        if documents:
            chunks = self._chunk_documents(documents, "stig_check")
            ids = self.vector_store.add_documents(chunks)
            logger.info(f"Indexed {len(ids)} STIG check chunks from {len(benchmarks)} checks")
            return len(ids)
        return 0

    def index_ssp_statements(self, statements: List[Dict[str, Any]]) -> int:
        """
        Index SSP implementation statements.

        Each statement links a control to an implementation narrative,
        enabling RAG to compare "what we say" vs "what cloud config shows."
        """
        documents = []
        for stmt in statements:
            metadata = {
                "doc_type": "ssp_statement",
                "system_id": stmt.get("system_id", ""),
                "control_id": stmt.get("control_id", ""),
                "framework": stmt.get("framework", ""),
                "responsibility": stmt.get("responsibility", ""),  # provider | customer | shared
                "last_updated": stmt.get("last_updated", ""),
            }
            documents.append(Document(
                page_content=f"SSP Implementation for {stmt.get('control_id', '')}:\n\n{stmt.get('narrative', '')}",
                metadata=metadata,
            ))

        if documents:
            chunks = self._chunk_documents(documents, "ssp_statement")
            ids = self.vector_store.add_documents(chunks)
            logger.info(f"Indexed {len(ids)} SSP statement chunks")
            return len(ids)
        return 0

    def index_evidence_metadata(self, artifacts: List[Dict[str, Any]]) -> int:
        """
        Index evidence artifact metadata for retrieval during assessments.

        Enables RAG to find relevant evidence by control, provider, date, type.
        """
        documents = []
        for artifact in artifacts:
            metadata = {
                "doc_type": "evidence_summary",
                "artifact_id": artifact.get("artifact_id", ""),
                "artifact_type": artifact.get("artifact_type", ""),
                "system_id": artifact.get("system_id", ""),
                "provider": artifact.get("provider", ""),
                "collected_at": artifact.get("collected_at", ""),
                "control_ids": ",".join(artifact.get("control_ids", [])),
            }

            content = (
                f"Evidence: {artifact.get('artifact_type', '')} "
                f"from {artifact.get('provider', '')} "
                f"collected {artifact.get('collected_at', '')}. "
                f"Controls: {', '.join(artifact.get('control_ids', []))}. "
                f"Tags: {artifact.get('tags', {})}"
            )

            documents.append(Document(
                page_content=content,
                metadata=metadata,
            ))

        if documents:
            ids = self.vector_store.add_documents(documents)
            logger.info(f"Indexed {len(ids)} evidence metadata entries")
            return len(ids)
        return 0

    def index_policy_documents(self, policies: List[Dict[str, Any]]) -> int:
        """Index organizational policy and procedure documents."""
        documents = []
        for policy in policies:
            metadata = {
                "doc_type": "policy_doc",
                "policy_id": policy.get("policy_id", ""),
                "title": policy.get("title", ""),
                "effective_date": policy.get("effective_date", ""),
                "mapped_controls": ",".join(policy.get("mapped_controls", [])),
            }
            documents.append(Document(
                page_content=f"Policy: {policy.get('title', '')}\n\n{policy.get('content', '')}",
                metadata=metadata,
            ))

        if documents:
            chunks = self._chunk_documents(documents, "policy_doc")
            ids = self.vector_store.add_documents(chunks)
            logger.info(f"Indexed {len(ids)} policy document chunks")
            return len(ids)
        return 0

    def _chunk_documents(self, documents: List[Document], doc_type: str) -> List[Document]:
        """Chunk documents using type-specific configuration."""
        config = CHUNK_CONFIGS.get(doc_type, CHUNK_CONFIGS["default"])

        try:
            from langchain.text_splitter import RecursiveCharacterTextSplitter

            splitter = RecursiveCharacterTextSplitter(
                chunk_size=config["chunk_size"],
                chunk_overlap=config["chunk_overlap"],
                separators=[config["separator"], "\n", " "],
            )
            return splitter.split_documents(documents)
        except ImportError:
            logger.warning("langchain text splitter not available — returning unchunked documents")
            return documents
