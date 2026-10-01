"""
Abstract Vector Memory Store Interface.

Defines the contract for vector embedding indexing and RAG retrieval.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseVectorMemory(ABC):
    """Abstract interface for AI agent vector memory persistence."""

    @abstractmethod
    async def add_documents(
        self, documents: List[str], metadatas: Optional[List[Dict[str, Any]]] = None
    ) -> List[str]:
        """Index text documents with metadata into vector store."""
        pass

    @abstractmethod
    async def similarity_search(
        self, query: str, k: int = 5
    ) -> List[Dict[str, Any]]:
        """Perform semantic similarity search against stored embeddings."""
        pass
