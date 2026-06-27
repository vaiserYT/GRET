from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class ResourceType(Enum):
    OBJECT = auto()
    ROOM = auto()
    SCRIPT = auto()
    SPRITE = auto()
    SOUND = auto()
    FONT = auto()
    TIMELINE = auto()
    SEQUENCE = auto()
    SHADER = auto()
    PATH = auto()
    NOTES = auto()
    BACKGROUND = auto()
    UNKNOWN = auto()


class EventType(Enum):
    CREATE = auto()
    DESTROY = auto()
    STEP = auto()
    ALARM = auto()
    DRAW = auto()
    DRAW_GUI = auto()
    KEYBOARD = auto()
    KEY_PRESS = auto()
    KEY_RELEASE = auto()
    MOUSE = auto()
    COLLISION = auto()
    OTHER = auto()
    ROOM_START = auto()
    ROOM_END = auto()
    ANIMATION_END = auto()
    USER = auto()
    CLEANUP = auto()
    UNKNOWN = auto()


class SuspicionLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4
    CRITICAL = 5


class ReferenceType(Enum):
    CREATE = auto()
    PLACE = auto()
    CALL = auto()
    READ = auto()
    WRITE = auto()
    INHERIT = auto()
    ASSIGN = auto()
    TRANSITION = auto()
    COLLISION = auto()
    REFERENCE = auto()
    DYNAMIC = auto()


@dataclass(frozen=True, slots=True)
class SourceLocation:
    resource_name: str
    resource_type: ResourceType
    file_path: Path
    line: int = 0
    column: int = 0
    context: str = ""


@dataclass(frozen=True, slots=True)
class Reference:
    source: SourceLocation
    target: str
    ref_type: ReferenceType

    def __lt__(self, other: Reference) -> bool:
        return (self.target, self.ref_type.name) < (other.target, other.ref_type.name)


@dataclass
class FlagInfo:
    index: int
    sets: list[Reference] = field(default_factory=list)
    gets: list[Reference] = field(default_factory=list)
    switch_cases: list[int] = field(default_factory=list)

    @property
    def set_count(self) -> int:
        return len(self.sets)

    @property
    def get_count(self) -> int:
        return len(self.gets)

    @property
    def never_set(self) -> bool:
        return self.set_count == 0

    @property
    def never_read(self) -> bool:
        return self.get_count == 0

    @property
    def read_before_write(self) -> bool:
        if not self.sets:
            return False
        for g in self.gets:
            for s in self.sets:
                if g.source.line < s.source.line:
                    return True
        return False

    @property
    def write_without_read(self) -> bool:
        return self.set_count > 0 and self.get_count == 0


@dataclass
class DialogueEntry:
    text_id: str
    text: str
    references: list[Reference] = field(default_factory=list)
    file_path: Optional[Path] = None


@dataclass
class ObjectEvent:
    event_type: EventType
    subtype: Optional[str]
    code: str
    line_start: int = 0
    line_end: int = 0


@dataclass
class ObjectInfo:
    name: str
    sprite: Optional[str] = None
    parent: Optional[str] = None
    mask: Optional[str] = None
    solid: bool = False
    persistent: bool = False
    events: dict[str, ObjectEvent] = field(default_factory=dict)
    path: Optional[Path] = None
    visible: bool = True
    depth: int = 0

    def get_event(self, event_type: EventType, subtype: Optional[str] = None) -> Optional[ObjectEvent]:
        key = f"{event_type.name}_{subtype or ''}"
        return self.events.get(key)


@dataclass
class RoomInstance:
    object_name: str
    x: int = 0
    y: int = 0
    instance_id: Optional[int] = None
    creation_code: Optional[str] = None
    scale_x: float = 1.0
    scale_y: float = 1.0
    rotation: float = 0.0
    colour: Optional[int] = None
    alpha: float = 1.0


@dataclass
class RoomView:
    x: int = 0
    y: int = 0
    w: int = 0
    h: int = 0
    port_w: int = 0
    port_h: int = 0
    follow_object: Optional[str] = None


@dataclass
class RoomInfo:
    name: str
    width: int = 0
    height: int = 0
    speed: int = 30
    persistent: bool = False
    instances: list[RoomInstance] = field(default_factory=list)
    views: list[RoomView] = field(default_factory=list)
    path: Optional[Path] = None
    creation_code: Optional[str] = None

    @property
    def object_names(self) -> set[str]:
        return {inst.object_name for inst in self.instances}


@dataclass
class ScriptInfo:
    name: str
    code: str = ""
    path: Optional[Path] = None
    arguments: list[str] = field(default_factory=list)
    is_anonymous: bool = False
    parent_function: Optional[str] = None


@dataclass
class SpriteInfo:
    name: str
    path: Optional[Path] = None
    width: int = 0
    height: int = 0
    frames: int = 1
    texture_page: Optional[str] = None


@dataclass
class SoundInfo:
    name: str
    path: Optional[Path] = None
    type: str = ""
    channels: int = 1
    bitrate: int = 0


@dataclass
class FontInfo:
    name: str
    path: Optional[Path] = None
    size: int = 12
    bold: bool = False
    italic: bool = False


@dataclass
class RoomTransition:
    source_room: str
    target_room: str
    source_location: SourceLocation
    transition_type: str = "room_goto"
    conditional: Optional[str] = None


@dataclass
class SuspiciousResource:
    name: str
    resource_type: ResourceType
    score: int
    level: SuspicionLevel
    reasons: list[str] = field(default_factory=list)
    details: str = ""

    def __lt__(self, other: SuspiciousResource) -> bool:
        return self.score > other.score


@dataclass
class PlotBranch:
    plot_value: int
    description: str = ""
    references: list[Reference] = field(default_factory=list)
    incoming_states: list[int] = field(default_factory=list)
    outgoing_states: list[int] = field(default_factory=list)
    reachable: bool = True
    has_code: bool = True


@dataclass
class AnalysisResult:
    resource_name: str
    analyzer: str
    findings: list[str] = field(default_factory=list)
    score: float = 0.0


@dataclass
class ProjectIndex:
    project_path: Path
    game_name: str = ""
    objects: dict[str, ObjectInfo] = field(default_factory=dict)
    rooms: dict[str, RoomInfo] = field(default_factory=dict)
    scripts: dict[str, ScriptInfo] = field(default_factory=dict)
    sprites: dict[str, SpriteInfo] = field(default_factory=dict)
    sounds: dict[str, SoundInfo] = field(default_factory=dict)
    fonts: dict[str, FontInfo] = field(default_factory=dict)
    timelines: dict[str, str] = field(default_factory=dict)
    sequences: dict[str, str] = field(default_factory=dict)
    dialogues: dict[str, DialogueEntry] = field(default_factory=dict)
    flags: dict[int, FlagInfo] = field(default_factory=dict)
    transitions: list[RoomTransition] = field(default_factory=list)
    call_targets: dict[str, list[Reference]] = field(default_factory=dict)
    all_resources: dict[str, ResourceType] = field(default_factory=dict)

    def get_resource_type(self, name: str) -> Optional[ResourceType]:
        return self.all_resources.get(name)

    def resource_exists(self, name: str) -> bool:
        return name in self.all_resources

    def total_objects(self) -> int:
        return len(self.objects)

    def total_rooms(self) -> int:
        return len(self.rooms)

    def total_scripts(self) -> int:
        return len(self.scripts)

    def total_sprites(self) -> int:
        return len(self.sprites)

    def total_sounds(self) -> int:
        return len(self.sounds)

    def total_resources(self) -> int:
        return len(self.all_resources)


def suspicion_level_from_score(score: int) -> SuspicionLevel:
    if score >= 100:
        return SuspicionLevel.CRITICAL
    if score >= 60:
        return SuspicionLevel.VERY_HIGH
    if score >= 30:
        return SuspicionLevel.HIGH
    if score >= 10:
        return SuspicionLevel.MEDIUM
    if score >= 1:
        return SuspicionLevel.LOW
    return SuspicionLevel.NONE
