"""
Vector Store Configuration — pgvector, Chroma, or OpenSearch backends.

Stores embeddings for compliance knowledge:
  - NIST 800-53 control descriptions + assessment objectives
  - FedRAMP implementation guidance
  - SSP implementation statements
  - STIG check content + fix text
  - Evidence artifact metadata
  - Organizational policies and procedures
"""

import logging
from typing import Any, Dict, List, Optional

from django.conf import settings

logger = logging.getLogger(__name__)


class VectorStoreManager:
    """
    Manages vector store connections and operations.
    Supports pgvector, Chroma, and OpenSearch backends.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or getattr(settings, "VECTOR_DB", {})
        self.backend = self.config.get("BACKEND", "pgvector")
        self.collection = self.config.get("COLLECTION", "ato_compliance")
        self.embedding_model = self.config.get("EMBEDDING_MODEL", "text-embedding-3-small")
        self.dimensions = self.config.get("EMBEDDING_DIMENSIONS", 1536)
        self._store = None

    def get_store(self):
        """Get or create the vector store instance."""
        if self._store is not None:
            return self._store

        if self.backend == "pgvector":
            self._store = self._init_pgvector()
        elif self.backend == "chroma":
            self._store = self._init_chroma()
        elif self.backend == "opensearch":
            self._store = self._init_opensearch()
        else:
            raise ValueError(f"Unsupported vector store backend: {self.backend}")

        return self._store

    def _init_pgvector(self):
        """Initialize pgvector store via LangChain."""
        try:
            from langchain_community.vectorstores import PGVector
            from langchain_openai import OpenAIEmbeddings

            embeddings = OpenAIEmbeddings(model=self.embedding_model)
            db_settings = settings.DATABASES["default"]
            connection_string = (
                f"postgresql+psycopg2://{db_settings['USER']}:{db_settings['PASSWORD']}"
                f"@{db_settings['HOST']}:{db_settings['PORT']}/{db_settings['NAME']}"
            )

            store = PGVector(
                collection_name=self.collection,
                connection_string=connection_string,
                embedding_function=embeddings,
            )
            logger.info(f"pgvector store initialized: collection={self.collection}")
            return store
        except ImportError as e:
            logger.error(f"pgvector dependencies missing: {e}")
            return None

    def _init_chroma(self):
        """Initialize Chroma vector store."""
        try:
            from langchain_chroma import Chroma
            from langchain_openai import OpenAIEmbeddings

            embeddings = OpenAIEmbeddings(model=self.embedding_model)
            store = Chroma(
                collection_name=self.collection,
                embedding_function=embeddings,
                persist_directory="./chroma_data",
            )
            logger.info(f"Chroma store initialized: collection={self.collection}")
            return store
        except ImportError as e:
            logger.error(f"Chroma dependencies missing: {e}")
            return None

    def _init_opensearch(self):
        """Initialize OpenSearch vector store."""
        try:
            from langchain_community.vectorstores import OpenSearchVectorSearch
            from langchain_openai import OpenAIEmbeddings

            embeddings = OpenAIEmbeddings(model=self.embedding_model)
            opensearch_url = self.config.get("OPENSEARCH_URL", "http://localhost:9200")

            store = OpenSearchVectorSearch(
                opensearch_url=opensearch_url,
                index_name=self.collection,
                embedding_function=embeddings,
            )
            logger.info(f"OpenSearch store initialized: index={self.collection}")
            return store
        except ImportError as e:
            logger.error(f"OpenSearch dependencies missing: {e}")
            return None

    def add_documents(self, documents: List[Any], **kwargs) -> List[str]:
        """Add documents to the vector store."""
        store = self.get_store()
        if store is None:
            logger.warning("Vector store not available — skipping document addition")
            return []
        return store.add_documents(documents, **kwargs)

    def similarity_search(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> List[Any]:
        """Search for similar documents."""
        store = self.get_store()
        if store is None:
            logger.warning("Vector store not available — returning empty results")
            return []
        return store.similarity_search(query, k=k, filter=filter, **kwargs)

    def similarity_search_with_score(
        self,
        query: str,
        k: int = 5,
        filter: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> List[Any]:
        """Search for similar documents with relevance scores."""
        store = self.get_store()
        if store is None:
            return []
        return store.similarity_search_with_score(query, k=k, filter=filter, **kwargs)
