from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RoomInstance:
    object_id: int
    x: int
    y: int
    instance_id: int = -1
    creation_code_id: int = -1
    scale_x: float = 1.0
    scale_y: float = 1.0
    rotation: float = 0.0
    colour: int = 0
    alpha: float = 1.0
    layer_depth: int = 0
    image_index: float = 0.0
    image_speed: float = 1.0
    persistent: bool = False

    @property
    def object_name(self) -> str:
        return ""


@dataclass
class RoomLayer:
    name: str = ""
    depth: int = 0
    visible: bool = True
    layer_type: int = 0
    instances: list[RoomInstance] = field(default_factory=list)
    tiles: list = field(default_factory=list)


@dataclass
class RoomView:
    enabled: bool = False
    x: int = 0
    y: int = 0
    w: int = 0
    h: int = 0
    port_x: int = 0
    port_y: int = 0
    port_w: int = 0
    port_h: int = 0
    border_x: int = 0
    border_y: int = 0
    speed: int = -1
    follow_object_id: int = -1


@dataclass
class RoomBackground:
    enabled: bool = False
    visible: bool = True
    foreground: bool = False
    background_id: int = -1
    x: int = 0
    y: int = 0
    tile_x: bool = False
    tile_y: bool = False
    hspeed: int = 0
    vspeed: int = 0
    alpha: float = 1.0
    stretch: bool = False


@dataclass
class RoomDef:
    id: int
    name: str
    caption: str = ""
    width: int = 640
    height: int = 480
    speed: int = 30
    persistent: bool = False
    colour: int = 0
    creation_code_id: int = -1
    flags: int = 0
    physics_top: int = 0
    physics_left: int = 0
    physics_right: int = 1024
    physics_bottom: int = 768
    physics_gravity_x: float = 0.0
    physics_gravity_y: float = 10.0
    meters_per_pixel: float = 0.1
    instances: list[RoomInstance] = field(default_factory=list)
    layers: list[RoomLayer] = field(default_factory=list)
    views: list[RoomView] = field(default_factory=list)
    backgrounds: list[RoomBackground] = field(default_factory=list)

    @property
    def object_ids(self) -> set[int]:
        ids: set[int] = set()
        for inst in self.instances:
            ids.add(inst.object_id)
        for layer in self.layers:
            for inst in layer.instances:
                ids.add(inst.object_id)
        return ids

    @property
    def object_count(self) -> int:
        return len(self.instances) + sum(len(l.instances) for l in self.layers)
