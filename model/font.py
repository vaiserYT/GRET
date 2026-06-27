from __future__ import annotations

from dataclasses import dataclass


@dataclass
class FontGlyph:
    character: int = 0
    x: int = 0
    y: int = 0
    w: int = 0
    h: int = 0
    shift_x: int = 0
    shift_y: int = 0
    texture_page: int = -1


@dataclass
class FontDef:
    id: int
    name: str
    size: int = 12
    bold: bool = False
    italic: bool = False
    charset: int = 0
    antialias: int = 1
    range_min: int = 32
    range_max: int = 127
    glyphs: list[FontGlyph] = None
    texture_page: int = -1

    def __post_init__(self):
        if self.glyphs is None:
            self.glyphs = []

    def __hash__(self) -> int:
        return hash(self.id)
