from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from core.database import AnalysisDatabase
from core.graph import DependencyGraph
from core.models import ProjectIndex


class BaseAnalyzer(ABC):
    def __init__(self, index: ProjectIndex, graph: DependencyGraph, database: AnalysisDatabase) -> None:
        self.index = index
        self.graph = graph
        self.database = database

    @abstractmethod
    def analyze(self) -> None:
        ...

    @abstractmethod
    def name(self) -> str:
        ...

    def log(self, message: str) -> None:
        self.database.add_finding(f"[{self.name()}] {message}")
