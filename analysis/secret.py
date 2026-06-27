"""SecretFinder: thin wrapper over SemanticReferenceGraph suspicious_items.

Every heuristic is now a graph property query. No independent analysis.
"""
from __future__ import annotations

from ir.semantic_graph import SuspiciousItem, SemanticReferenceGraph

# Re-export for backward-compatible imports
__all__ = ["SecretFinder", "SuspiciousItem"]


class SecretFinder:
    """Delegates entirely to SemanticReferenceGraph.suspicious_resources()."""

    def __init__(self, game, graph: SemanticReferenceGraph) -> None:
        self.game = game
        self.graph = graph

    def find_all(self, progress_callback=None) -> list[SuspiciousItem]:
        return self.graph.suspicious_resources()

    def top_suspicious(self, limit: int = 100) -> list[SuspiciousItem]:
        items = self.graph.suspicious_resources()
        return items[:limit]
