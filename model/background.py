from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class BackgroundDef:
    id: int
    name: str
    width: int = 0
    height: int = 0
    transparent: bool = True
    smooth: bool = False
    preload: bool = True
    texture_page: int = -1
    texture_x: int = 0
    texture_y: int = 0
    texture_w: int = 0
    texture_h: int = 0
    source_x: int = 0
    source_y: int = 0
    source_w: int = 0
    source_h: int = 0
    tile_h: bool = False
    tile_v: bool = False
    hspeed: int = 0
    vspeed: int = 0

    def __hash__(self) -> int:
        return hash(self.id)
