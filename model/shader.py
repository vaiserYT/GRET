from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ShaderDef:
    id: int
    name: str
    vertex_source: str = ""
    fragment_source: str = ""
    type: int = 0

    def __hash__(self) -> int:
        return hash(self.id)
