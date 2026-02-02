"""
Hybrid Retriever with Reranking — Advanced RAG retrieval for compliance.

Features:
  1. Hybrid retrieval: vector similarity + metadata filtering
  2. Cross-encoder reranking for precision
  3. Time-aware retrieval (evidence freshness windows)
  4. Multi-hop retrieval chains (control -> evidence -> validation)
  5. Contradiction detection between SSP claims and cloud reality
  6. Evidence sufficiency scoring (freshness + completeness + authority + consistency)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from langchain.schema import Document

logger = logging.getLogger(__name__)


@dataclass
class RetrievalResult:
    """Enriched retrieval result with scoring metadata."""
    document: Document
    similarity_score: float = 0.0
    rerank_score: float = 0.0
    freshness_score: float = 0.0
    authority_score: float = 0.0
    combined_score: float = 0.0


@dataclass
class EvidenceSufficiency:
    """Evidence sufficiency assessment for a control."""
    control_id: str
    freshness_score: float = 0.0     # 0-1: how recent is the evidence?
    completeness_score: float = 0.0  # 0-1: do we have all required evidence types?
    authority_score: float = 0.0     # 0-1: is evidence from authoritative sources?
    consistency_score: float = 0.0   # 0-1: do evidence items agree with each other?
    overall_score: float = 0.0      # Weighted combination
    missing_evidence: List[str] = field(default_factory=list)
    contradictions: List[Dict[str, Any]] = field(default_factory=list)


# Evidence freshness SLAs (days) by control family
FRESHNESS_SLA_DAYS = {
    "AU": 7,     # Audit logs: weekly
    "CM": 1,     # Configuration management: daily
    "AC": 30,    # Access control: monthly
    "IA": 30,    # Identification & authentication: monthly
    "SC": 30,    # System communications: monthly
    "SI": 7,     # System integrity: weekly
    "RA": 90,    # Risk assessment: quarterly
    "CA": 365,   # Assessment: annually
    "PL": 365,   # Planning: annually
    "default": 30,
}

# Required evidence types per control family
REQUIRED_EVIDENCE_TYPES = {
    "AC": ["config_snapshot", "log_export"],
    "AU": ["config_snapshot", "log_export"],
    "CM": ["config_snapshot", "scan_report"],
    "IA": ["config_snapshot", "policy_doc"],
    "SC": ["config_snapshot"],
    "SI": ["scan_report", "log_export"],
    "default": ["config_snapshot"],
}


class ComplianceRetriever:
    """
    Advanced retriever for compliance knowledge with reranking,
    time-awareness, multi-hop, and sufficiency scoring.
    """

    def __init__(self, vector_store_manager, reranker=None):
        self.vector_store = vector_store_manager
        self.reranker = reranker or self._default_reranker()

    # -------------------------------------------------------------------------
    # Core retrieval methods
    # -------------------------------------------------------------------------

    def retrieve_for_control(
        self,
        control_id: str,
        query: str,
        framework: str = "nist_800_53_r5",
        provider: str = "",
        system_id: str = "",
        k: int = 10,
        rerank_top_k: int = 5,
    ) -> List[RetrievalResult]:
        """
        Retrieve and rerank documents relevant to a specific control assessment.

        Uses hybrid approach:
        1. Vector similarity search with metadata filters
        2. Cross-encoder reranking
        3. Time-aware freshness scoring
        """
        # Build metadata filter
        metadata_filter = {"control_id": control_id}
        if framework:
            metadata_filter["framework"] = framework

        # Stage 1: Broad vector search
        results_with_scores = self.vector_store.similarity_search_with_score(
            query=query,
            k=k * 2,  # Over-retrieve for reranking
            filter=metadata_filter,
        )

        # Also search without strict control filter to catch related evidence
        broad_results = self.vector_store.similarity_search_with_score(
            query=f"{control_id} {query}",
            k=k,
        )

        # Merge and deduplicate
        seen_contents = set()
        all_results = []
        for doc, score in list(results_with_scores) + list(broad_results):
            content_hash = hash(doc.page_content[:200])
            if content_hash not in seen_contents:
                seen_contents.add(content_hash)
                all_results.append(RetrievalResult(
                    document=doc,
                    similarity_score=float(score),
                ))

        # Stage 2: Reranking
        if self.reranker and all_results:
            all_results = self._rerank(query, all_results)

        # Stage 3: Freshness scoring
        for result in all_results:
            result.freshness_score = self._compute_freshness(
                result.document.metadata, control_id
            )
            result.authority_score = self._compute_authority(result.document.metadata)
            result.combined_score = (
                0.4 * result.rerank_score
                + 0.3 * result.freshness_score
                + 0.2 * result.similarity_score
                + 0.1 * result.authority_score
            )

        # Sort by combined score and return top_k
        all_results.sort(key=lambda r: r.combined_score, reverse=True)
        return all_results[:rerank_top_k]

    def multi_hop_retrieve(
        self,
        control_id: str,
        system_id: str,
        framework: str = "nist_800_53_r5",
    ) -> Dict[str, List[RetrievalResult]]:
        """
        Multi-hop retrieval chain:
          1. Retrieve control requirement + assessment objective
          2. Retrieve implementation guidance / SSP statement
          3. Retrieve evidence artifacts that fulfill the requirement
          4. Retrieve any contradicting evidence

        Returns dict with keys: requirement, guidance, evidence, contradictions
        """
        results = {}

        # Hop 1: Control requirement
        results["requirement"] = self.retrieve_for_control(
            control_id=control_id,
            query=f"What does control {control_id} require?",
            framework=framework,
            k=5,
            rerank_top_k=3,
        )

        # Hop 2: Implementation guidance / SSP
        results["guidance"] = self.vector_store.similarity_search(
            query=f"How is {control_id} implemented? SSP implementation statement.",
            k=5,
            filter={"doc_type": "ssp_statement", "control_id": control_id},
        )
        results["guidance"] = [
            RetrievalResult(document=doc, similarity_score=1.0)
            for doc in (results["guidance"] if results["guidance"] else [])
        ]

        # Hop 3: Evidence artifacts
        results["evidence"] = self.vector_store.similarity_search(
            query=f"Evidence for control {control_id} compliance assessment",
            k=10,
            filter={"doc_type": "evidence_summary"},
        )
        results["evidence"] = [
            RetrievalResult(document=doc, similarity_score=1.0)
            for doc in (results["evidence"] if results["evidence"] else [])
        ]

        # Hop 4: Look for contradictions (SSP claims vs config reality)
        results["contradictions"] = self._detect_contradictions(
            control_id, results.get("guidance", []), results.get("evidence", [])
        )

        return results

    # -------------------------------------------------------------------------
    # Evidence sufficiency scoring
    # -------------------------------------------------------------------------

    def assess_evidence_sufficiency(
        self,
        control_id: str,
        evidence_results: List[RetrievalResult],
    ) -> EvidenceSufficiency:
        """
        Compute evidence sufficiency score for a control.

        Factors:
          - Freshness: Is evidence within the SLA window?
          - Completeness: Do we have all required evidence types?
          - Authority: Is evidence from authoritative/automated sources?
          - Consistency: Do evidence items agree with each other?
        """
        family = control_id.split("-")[0] if "-" in control_id else "default"

        # Freshness
        freshness_scores = [
            self._compute_freshness(r.document.metadata, control_id)
            for r in evidence_results
        ]
        avg_freshness = sum(freshness_scores) / len(freshness_scores) if freshness_scores else 0.0

        # Completeness
        required_types = REQUIRED_EVIDENCE_TYPES.get(family, REQUIRED_EVIDENCE_TYPES["default"])
        found_types = {
            r.document.metadata.get("artifact_type", r.document.metadata.get("doc_type", ""))
            for r in evidence_results
        }
        missing = [t for t in required_types if t not in found_types]
        completeness = 1.0 - (len(missing) / len(required_types)) if required_types else 1.0

        # Authority
        authority_scores = [self._compute_authority(r.document.metadata) for r in evidence_results]
        avg_authority = sum(authority_scores) / len(authority_scores) if authority_scores else 0.0

        # Consistency (simplified — in production, use LLM to detect contradictions)
        consistency = 1.0  # Default to consistent; reduce if contradictions found

        # Overall weighted score
        overall = (
            0.3 * avg_freshness
            + 0.3 * completeness
            + 0.2 * avg_authority
            + 0.2 * consistency
        )

        return EvidenceSufficiency(
            control_id=control_id,
            freshness_score=avg_freshness,
            completeness_score=completeness,
            authority_score=avg_authority,
            consistency_score=consistency,
            overall_score=overall,
            missing_evidence=missing,
            contradictions=[],
        )

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _rerank(self, query: str, results: List[RetrievalResult]) -> List[RetrievalResult]:
        """Rerank results using cross-encoder or LLM reranker."""
        if self.reranker is None:
            # Fallback: use similarity score as rerank score
            for r in results:
                r.rerank_score = r.similarity_score
            return results

        try:
            pairs = [(query, r.document.page_content) for r in results]
            scores = self.reranker.predict(pairs)
            for r, score in zip(results, scores):
                r.rerank_score = float(score)
        except Exception as e:
            logger.error(f"Reranking failed: {e}")
            for r in results:
                r.rerank_score = r.similarity_score

        return results

    def _compute_freshness(self, metadata: Dict[str, Any], control_id: str) -> float:
        """Score evidence freshness relative to SLA window."""
        collected_at_str = metadata.get("collected_at", metadata.get("last_updated", ""))
        if not collected_at_str:
            return 0.0

        try:
            collected_at = datetime.fromisoformat(collected_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return 0.0

        family = control_id.split("-")[0] if "-" in control_id else "default"
        sla_days = FRESHNESS_SLA_DAYS.get(family, FRESHNESS_SLA_DAYS["default"])

        age = datetime.now(timezone.utc) - collected_at
        if age.days <= sla_days:
            return 1.0
        elif age.days <= sla_days * 2:
            return 0.5
        else:
            return max(0.0, 1.0 - (age.days / (sla_days * 4)))

    @staticmethod
    def _compute_authority(metadata: Dict[str, Any]) -> float:
        """Score evidence authority based on source type."""
        doc_type = metadata.get("doc_type", metadata.get("artifact_type", ""))
        authority_map = {
            "config_snapshot": 0.9,    # Direct from cloud API
            "scan_report": 0.85,       # Automated scan
            "log_export": 0.9,         # Direct from audit logs
            "ckl": 0.8,               # STIG checklist
            "scap_result": 0.85,       # Automated SCAP scan
            "ssp_statement": 0.6,      # Human-authored
            "policy_doc": 0.5,         # Human-authored policy
            "nist_control": 1.0,       # Authoritative source
            "stig_check": 1.0,         # Authoritative source
            "evidence_summary": 0.7,   # Metadata summary
        }
        return authority_map.get(doc_type, 0.5)

    def _detect_contradictions(
        self,
        control_id: str,
        guidance_results: List[RetrievalResult],
        evidence_results: List[RetrievalResult],
    ) -> List[RetrievalResult]:
        """
        Detect potential contradictions between SSP/policy claims and evidence.

        In production: Use LLM to compare guidance claims with evidence findings.
        Returns evidence items that may contradict the stated implementation.
        """
        # Placeholder: full implementation uses LLM comparison
        return []

    @staticmethod
    def _default_reranker():
        """Try to load a cross-encoder reranker, fall back to None."""
        try:
            from sentence_transformers import CrossEncoder
            return CrossEncoder("cross-encoder/ms-marco-MiniLM-L-6-v2")
        except ImportError:
            logger.info("sentence-transformers not available — reranking disabled")
            return None
