from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TimelineMoment:
    step: int = 0
    code_id: int = -1
    code_offset: int = 0
    code_length: int = 0


@dataclass
class TimelineDef:
    id: int
    name: str
    moments: list[TimelineMoment] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)
