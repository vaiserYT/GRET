from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SoundDef:
    id: int
    name: str
    type: int = 0
    file: str = ""
    volume: float = 1.0
    pitch: float = 1.0
    preload: bool = True
    audio_group: int = -1
    bitrate: int = 0
    compression: int = 0
    data_offset: int = 0
    data_size: int = 0
    effects: int = 0

    def __hash__(self) -> int:
        return hash(self.id)
