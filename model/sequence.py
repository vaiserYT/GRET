from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SequenceKeyframe:
    time: float = 0.0
    value: float = 0.0
    curve: int = 0


@dataclass
class SequenceTrack:
    name: str = ""
    type: int = 0
    target_id: int = -1
    keyframes: list[SequenceKeyframe] = field(default_factory=list)


@dataclass
class SequenceDef:
    id: int
    name: str
    length: float = 1.0
    tracks: list[SequenceTrack] = field(default_factory=list)

    def __hash__(self) -> int:
        return hash(self.id)
