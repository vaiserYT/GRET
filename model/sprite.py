from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SpriteFrame:
    texture_page: int = -1
    texture_x: int = 0
    texture_y: int = 0
    texture_w: int = 0
    texture_h: int = 0
    offset_x: int = 0
    offset_y: int = 0
    source_x: int = 0
    source_y: int = 0
    source_w: int = 0
    source_h: int = 0


@dataclass
class SpriteDef:
    id: int
    name: str
    width: int = 0
    height: int = 0
    margin_left: int = 0
    margin_right: int = 0
    margin_top: int = 0
    margin_bottom: int = 0
    bbox_left: int = 0
    bbox_right: int = 0
    bbox_top: int = 0
    bbox_bottom: int = 0
    transparent: bool = True
    smooth: bool = False
    preload: bool = True
    frames: list[SpriteFrame] = field(default_factory=list)
    texture_group: int = -1
    has_collision_mask: bool = False
    mask_shape: int = 0
    alpha_tolerance: int = 0
    separate_mask: bool = False
    origin_x: int = 0
    origin_y: int = 0
    frame_count: int = 1

    def __hash__(self) -> int:
        return hash(self.id)
