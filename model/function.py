from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FunctionArg:
    name: str = ""
    default_value: int = 0
    has_default: bool = False


@dataclass
class FunctionDef:
    id: int
    name: str
    code_id: int = -1
    code_offset: int = 0
    code_length: int = 0
    owner_id: int = -1
    owner_type: int = 0
    args: list[FunctionArg] = field(default_factory=list)
    arg_count: int = 0
    locals_count: int = 0
    is_static: bool = False
    is_constructor: bool = False
    return_type: int = 0

    @property
    def display_name(self) -> str:
        return self.name

    @property
    def is_script(self) -> bool:
        return self.owner_type == 0

    @property
    def is_object_event(self) -> bool:
        return self.owner_type == 1

    def __hash__(self) -> int:
        return hash(self.id)
