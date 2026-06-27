from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScriptDef:
    id: int
    name: str
    code_id: int = -1
    code_offset: int = 0
    code_length: int = 0
    is_global: bool = False
    arguments: list[str] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        return self.name

    def __hash__(self) -> int:
        return hash(self.id)
