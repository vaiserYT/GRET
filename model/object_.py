from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class EventType(IntEnum):
    CREATE = 0
    DESTROY = 1
    ALARM = 2
    STEP = 3
    COLLISION = 4
    KEYBOARD = 5
    MOUSE = 6
    OTHER = 7
    DRAW = 8
    DRAW_GUI = 9
    KEY_RELEASE = 10
    MOUSE_RELEASE = 11
    KEY_PRESS = 12
    MOUSE_PRESS = 13
    USER = 14
    ROOM_START = 15
    ROOM_END = 16
    ANIMATION_END = 17
    ANIMATION_START = 18
    CLEANUP = 19
    STEP_BEGIN = 20
    STEP_MIDDLE = 21
    STEP_END = 22
    PRE_DRAW = 23
    DRAW_BEGIN = 24
    DRAW_END = 25
    DRAW_GUI_BEGIN = 26
    DRAW_GUI_END = 27
    GAME_START = 28
    GAME_END = 29
    UNKNOWN = 99


EVENT_NAMES: dict[int, str] = {
    0: "Create",
    1: "Destroy",
    2: "Alarm",
    3: "Step",
    4: "Collision",
    5: "Keyboard",
    6: "Mouse",
    7: "Other",
    8: "Draw",
    9: "Draw GUI",
    10: "Key Release",
    11: "Mouse Release",
    12: "Key Press",
    13: "Mouse Press",
    14: "User",
    15: "Room Start",
    16: "Room End",
    17: "Animation End",
    18: "Animation Start",
    19: "Cleanup",
    20: "Step Begin",
    21: "Step Middle",
    22: "Step End",
    23: "Pre Draw",
    24: "Draw Begin",
    25: "Draw End",
    26: "Draw GUI Begin",
    27: "Draw GUI End",
    28: "Game Start",
    29: "Game End",
}


@dataclass
class ActionDef:
    lib_id: int = 0
    id: int = 0
    kind: int = 0
    use_relative: bool = False
    is_question: bool = False
    use_apply_to: bool = False
    exe_type: int = 0
    action_name: int = 0
    args_count: int = 0
    code_id: int = -1
    who: int = 0
    relative: bool = False
    is_not: bool = False


@dataclass
class EventDef:
    event_type: int
    subtype: int
    code_id: int = -1
    code_length: int = 0
    code_offset: int = 0
    actions: list[ActionDef] = field(default_factory=list)


@dataclass
class ObjectDef:
    id: int
    name: str
    sprite_index: int = -1
    mask_index: int = -1
    parent_index: int = -1
    solid: bool = False
    persistent: bool = False
    visible: bool = True
    depth: int = 0
    events: list[EventDef] = field(default_factory=list)
    physics: bool = False
    physics_shape: int = 0

    @property
    def sprite_name(self) -> str:
        return ""

    @property
    def parent_name(self) -> str:
        return ""

    def events_by_type(self, event_type: int) -> list[EventDef]:
        return [e for e in self.events if e.event_type == event_type]

    def has_event(self, event_type: int, subtype: int = 0) -> bool:
        return any(e.event_type == event_type and e.subtype == subtype for e in self.events)

    @property
    def has_create(self) -> bool:
        return self.has_event(0)

    @property
    def has_step(self) -> bool:
        return self.has_event(3)

    @property
    def has_draw(self) -> bool:
        return self.has_event(8)

    @property
    def has_alarm(self) -> bool:
        return any(e.event_type == 2 for e in self.events)

    @property
    def has_any_event(self) -> bool:
        return len(self.events) > 0

    @property
    def event_count(self) -> int:
        return len(self.events)

    def event_summary(self) -> str:
        names = []
        for e in self.events:
            en = EVENT_NAMES.get(e.event_type, f"EV_{e.event_type}")
            if e.subtype > 0:
                names.append(f"{en}({e.subtype})")
            else:
                names.append(en)
        return ", ".join(names)
