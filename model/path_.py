from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PathPoint:
    x: float = 0.0
    y: float = 0.0
    speed: float = 100.0


@dataclass
class PathDef:
    id: int
    name: str
    smooth: bool = False
    closed: bool = False
    precision: int = 4
    points: list[PathPoint] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)
