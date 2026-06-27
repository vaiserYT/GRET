from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from binary.strg import StringTable
from model.object_ import ObjectDef
from model.room_ import RoomDef
from model.sprite import SpriteDef
from model.sound import SoundDef
from model.font import FontDef
from model.code_ import CodeEntry
from model.function import FunctionDef
from model.variable import VariableDef
from model.timeline import TimelineDef
from model.path_ import PathDef
from model.shader import ShaderDef
from model.sequence import SequenceDef
from model.background import BackgroundDef


@dataclass
class GameWindow:
    width: int = 0
    height: int = 0
    fullscreen: bool = False
    vsync: bool = False
    colour: int = 0
    speed: int = 60
    game_id: int = 0
    company: str = ""
    product: str = ""
    version: str = ""
    info: str = ""


@dataclass
class TexturePage:
    name: str = ""
    width: int = 0
    height: int = 0
    data_offset: int = 0
    data_size: int = 0
    index: int = 0


@dataclass
class AudioGroup:
    name: str = ""
    index: int = 0


class Game:
    def __init__(self) -> None:
        self.path: Optional[Path] = None
        self.window = GameWindow()
        self.strings = StringTable()

        # Raw resource dicts (by ID)
        self.objects: dict[int, ObjectDef] = {}
        self.rooms: dict[int, RoomDef] = {}
        self.sprites: dict[int, SpriteDef] = {}
        self.sounds: dict[int, SoundDef] = {}
        self.fonts: dict[int, FontDef] = {}
        self.variables: dict[int, VariableDef] = {}
        self.functions: dict[str, FunctionDef] = {}
        self.code_entries: dict[int, CodeEntry] = {}
        self.code_offsets: dict[int, int] = {}

        # Other resource types
        self.scripts: dict[str, ScriptDef] = {}
        self.timelines: dict[str, TimelineDef] = {}
        self.paths: dict[str, PathDef] = {}
        self.shaders: dict[str, ShaderDef] = {}
        self.sequences: dict[str, SequenceDef] = {}
        self.backgrounds: dict[str, BackgroundDef] = {}

        self.texture_pages: list[TexturePage] = []
        self.audio_groups: list[AudioGroup] = []

        # IR — set after resolve()
        self.resolver = None
        self.rgraph = None

    def string(self, idx: int) -> str:
        return self.strings[idx] if 0 <= idx < len(self.strings) else f"<str_{idx}>"

    def object_by_id(self, obj_id: int) -> Optional[ObjectDef]:
        return self.objects.get(obj_id)

    def room_by_id(self, room_id: int) -> Optional[RoomDef]:
        return self.rooms.get(room_id)

    def sprite_by_id(self, sprite_id: int) -> Optional[SpriteDef]:
        return self.sprites.get(sprite_id)

    def sound_by_id(self, sound_id: int) -> Optional[SoundDef]:
        return self.sounds.get(sound_id)

    def object_by_name(self, name: str) -> Optional[ObjectDef]:
        for obj in self.objects.values():
            if obj.name == name:
                return obj
        return None

    def room_by_name(self, name: str) -> Optional[RoomDef]:
        for room in self.rooms.values():
            if room.name == name:
                return room
        return None

    @property
    def all_resources(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for obj in self.objects.values():
            result[obj.name] = "OBJECT"
        for room in self.rooms.values():
            result[room.name] = "ROOM"
        return result

    def summary(self) -> dict:
        return {
            "objects": len(self.objects),
            "rooms": len(self.rooms),
            "sprites": len(self.sprites),
            "sounds": len(self.sounds),
            "fonts": len(self.fonts),
            "scripts": len(self.scripts),
            "timelines": len(self.timelines),
            "paths": len(self.paths),
            "shaders": len(self.shaders),
            "sequences": len(self.sequences),
            "backgrounds": len(self.backgrounds),
            "functions": len(self.functions),
            "variables": len(self.variables),
            "code_entries": len(self.code_entries),
            "strings": len(self.strings),
            "texture_pages": len(self.texture_pages),
        }
